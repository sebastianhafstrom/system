package auth

import (
	"net/http"
	"strings"
)

func RoleMiddleware(allowedRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role := r.Header.Get("X-User-Role")
			if role == "" {
				http.Error(w, "unauthorized: role not found", http.StatusForbidden)
				return
			}

			for _, allowedRole := range allowedRoles {
				if strings.EqualFold(role, allowedRole) {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, "formidden: you do not have access to this resource", http.StatusForbidden)
		})
	}
}
