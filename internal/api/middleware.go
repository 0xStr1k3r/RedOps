package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/redops/redops/internal/auth"
)

type ctxKey string

const claimsKey ctxKey = "claims"

func newID() string { return uuid.NewString() }

// requireAuth validates Bearer JWT and injects claims.
func requireAuth(cfg Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if !strings.HasPrefix(h, "Bearer ") {
				writeErr(w, 401, "missing bearer token")
				return
			}
			c, err := auth.Parse(cfg.JWTSecret, strings.TrimPrefix(h, "Bearer "))
			if err != nil {
				writeErr(w, 401, "invalid or expired token")
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey, c)))
		})
	}
}

func claimsFrom(r *http.Request) (*auth.Claims, bool) {
	c, ok := r.Context().Value(claimsKey).(*auth.Claims)
	return c, ok
}

func actor(r *http.Request) string {
	if c, ok := claimsFrom(r); ok {
		return c.Username
	}
	return ""
}

func can(r *http.Request, required string) bool {
	c, ok := claimsFrom(r)
	if !ok {
		return false
	}
	return auth.CanAct(c.Role, required)
}
