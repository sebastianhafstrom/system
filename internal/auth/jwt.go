package auth

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	redisclient "github.com/sebastianhafstrom/system/internal/redis"
)

const (
	jwtSecret              = "secret"
	accessTokenExipration  = 15 * time.Minute
	refreshTokenExpiration = 7 * 24 * time.Hour
)

var ErrInvalidToken = errors.New("invalid token")
var ErrIPMismatch = errors.New("token IP mismatch")
var ErrUserAgentMismatch = errors.New("token user-agent mismatch")
var ErrTokenBlacklisted = errors.New("token has been blacklisted")

type Claims struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"useragent,omitempty"`
	jwt.RegisteredClaims
}

func GenerateJwt(username, role, ip, userAgent string) (string, string, error) {
	claims := &Claims{
		ID:        uuid.NewString(),
		Username:  username,
		Role:      role,
		IP:        ip,
		UserAgent: userAgent,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessTokenExipration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	accessToken, err := generateToken(claims)
	if err != nil {
		return "", "", err
	}

	refreshClaims := &Claims{
		Username:  username,
		Role:      role,
		IP:        ip,
		UserAgent: userAgent,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(refreshTokenExpiration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	refreshToken, err := generateToken(refreshClaims)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func BlacklistToken(ctx context.Context, id string, expiry time.Duration) error {
	redisClient := redisclient.GetClient()
	return redisClient.Set(ctx, id, "blacklisted", expiry).Err()
}

func IsBlacklisted(ctx context.Context, id string) (bool, error) {
	redisClient := redisclient.GetClient()
	result, err := redisClient.Get(ctx, id).Result()
	if err != nil {
		return false, nil
	}
	return result == "blacklisted", nil
}

func generateToken(claims *Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func ValidateJwt(ctx context.Context, tokenStr, ip, useragent string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (any, error) {
		return []byte(jwtSecret), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	if blacklisted, _ := IsBlacklisted(ctx, claims.ID); blacklisted {
		return nil, ErrTokenBlacklisted
	}

	if claims.IP != "" && claims.IP != ip {
		return nil, ErrIPMismatch
	}

	if claims.UserAgent != "" && claims.UserAgent != useragent {
		return nil, ErrUserAgentMismatch
	}

	return claims, nil
}
