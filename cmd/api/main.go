package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sebastianhafstrom/system/internal/auth"
	"github.com/sebastianhafstrom/system/internal/logger"
	redisclient "github.com/sebastianhafstrom/system/internal/redis"
	"github.com/sebastianhafstrom/system/internal/service"
	"github.com/sebastianhafstrom/system/internal/user"
	"github.com/urfave/negroni/v3"
)

// Prometheus metrics
var (
	loginAttempts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "login_attempts_total",
			Help: "Total number of login attempts",
		},
		[]string{"status"}, // success or failed
	)
	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Duration of HTTP requests.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"endpoint"},
	)
)

func Foo(w http.ResponseWriter, r *http.Request) {
	log := logger.Logger
	log.Info("Hello world!")
	service.ServiceFunc()
	fmt.Fprintf(w, "Welcome to Foo!")
}

func Bar(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to Bar!")
}

func FooBar(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Welcome to FooBar!")
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	log := logger.Logger.With("event", "register")

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Error("invalid request",
			"status", "failed",
			"error", err)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if err := user.RegisterUser(req.Username, req.Password, user.Role(req.Role)); err != nil {
		log.Error("failed to register user",
			"username", req.Username,
			"status", "failed",
			"error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Info("user registered successfully", "username", req.Username, "status", "success")

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "user registered successfully")
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	log := logger.Logger.With("event", "login")

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Error("invalid request",
			"status", "failed",
			"error", err)
		loginAttempts.WithLabelValues("failed").Inc()
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	user, err := user.AuthenticateUser(req.Username, req.Password)
	if err != nil {
		log.Error("failed to authenticate user",
			"username", req.Username,
			"status", "failed",
			"error", err)
		loginAttempts.WithLabelValues("failed").Inc()
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	ipAddress := r.RemoteAddr
	userAgent := r.UserAgent()
	accessToken, refreshToken, err := auth.GenerateJwt(user.Username, string(user.Role), ipAddress, userAgent)
	if err != nil {
		log.Error("failed to generate token",
			"username", req.Username,
			"status", "failed",
			"error", err)
		loginAttempts.WithLabelValues("failed").Inc()
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	log.Info("user logged in successfully", "username", req.Username, "status", "success")
	loginAttempts.WithLabelValues("success").Inc()

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int((7 * 24 * time.Hour).Seconds()),
	})

	json.NewEncoder(w).Encode(map[string]string{"access_token": accessToken})
}

func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	log := logger.Logger.With("event", "refresh")
	ctx := r.Context()

	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		log.Error("missing refresh token",
			"status", "failed",
			"error", err)
		http.Error(w, "missing refresh token", http.StatusUnauthorized)
		return
	}

	ipAddress := r.RemoteAddr
	userAgent := r.UserAgent()
	claims, err := auth.ValidateJwt(ctx, cookie.Value, "secret", ipAddress)
	if err != nil {
		log.Error("invalid refresh token",
			"status", "failed",
			"error", err)
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}

	accessToken, _, err := auth.GenerateJwt(claims.Username, claims.Role, ipAddress, userAgent)
	if err != nil {
		log.Error("failed to generate new access token",
			"status", "failed",
			"error", err)
		http.Error(w, "failed to generate new access token", http.StatusInternalServerError)
		return
	}

	log.Info("token refreshed successfully", "username", claims.Username, "status", "success")

	json.NewEncoder(w).Encode(map[string]string{"access_token": accessToken})
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	log := logger.Logger.With("event", "logout")
	ctx := r.Context()

	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		log.Error("missing refresh token",
			"status", "failed",
			"error", err)
		http.Error(w, "missing refresh token", http.StatusUnauthorized)
		return
	}

	ipAddress := r.RemoteAddr
	userAgent := r.UserAgent()
	claims, err := auth.ValidateJwt(ctx, cookie.Value, ipAddress, userAgent)
	if err != nil {
		log.Error("invalid refresh token",
			"status", "failed",
			"error", err)
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}

	blacklistExpiry := time.Until(claims.ExpiresAt.Time)
	if err := auth.BlacklistToken(ctx, claims.ID, blacklistExpiry); err != nil {
		log.Error("failed to blacklistrefresh token",
			"status", "failed",
			"error", err)
		http.Error(w, "failed to blacklist refresh token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
	})

	log.Info("successfully logged out", "username", claims.Username, "status", "success")

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "successfully logged out")
}

func log() {
	for ok := true; ok; ok = true {
		logger.Logger.Info("Hodwy")
		time.Sleep(5 * time.Second)
	}
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/foo", Foo).Methods("GET")
	router.HandleFunc("/bar", Bar).Methods("GET")

	protected := router.PathPrefix("/").Subrouter()
	protected.HandleFunc("/foobar", FooBar).Methods("GET")
	protected.Use(auth.JwtMiddleware)
	protected.Use(auth.RoleMiddleware(string(user.RoleAdmin)))

	router.HandleFunc("/auth/register", RegisterHandler).Methods("POST")
	router.HandleFunc("/auth/login", LoginHandler).Methods("POST")
	router.HandleFunc("/auth/refresh", RegisterHandler).Methods("POST")
	router.HandleFunc("/auth/logout", LogoutHandler).Methods("POST")

	router.Handle("/metrics", promhttp.Handler())

	n := negroni.Classic()
	n.UseHandler(router)

	go log()

	n.Run(":8080")
}

func init() {
	ctx := context.Background()
	redisclient.InitRedis(ctx)
	logger.Init()

	// Register Prometheus metrics
	prometheus.MustRegister(loginAttempts)
	prometheus.MustRegister(requestDuration)
}
