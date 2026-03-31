package sulis

import (
	"context"
	"net/http"
	"strings"
)

type contextKey int

const (
	userContextKey contextKey = iota
	sessionContextKey
)

// Authenticate returns HTTP middleware that validates the session token from
// either a cookie named "session" or an Authorization: Bearer header.
// On success, the User and Session are attached to the request context
// and can be retrieved with UserFromContext and SessionFromContext.
// On failure, the middleware responds with 401 Unauthorized.
func (s *Sulis) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		session, user, err := s.ValidateSession(r.Context(), token)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, user)
		ctx = context.WithValue(ctx, sessionContextKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// UserFromContext retrieves the authenticated user from the request context.
func UserFromContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userContextKey).(*User)
	return u, ok
}

// SessionFromContext retrieves the current session from the request context.
func SessionFromContext(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(sessionContextKey).(*Session)
	return s, ok
}

func extractToken(r *http.Request) string {
	// Try Authorization: Bearer <token> header first.
	if auth := r.Header.Get("Authorization"); auth != "" {
		if after, ok := strings.CutPrefix(auth, "Bearer "); ok {
			return strings.TrimSpace(after)
		}
	}

	// Fall back to cookie.
	if cookie, err := r.Cookie("session"); err == nil {
		return cookie.Value
	}

	return ""
}
