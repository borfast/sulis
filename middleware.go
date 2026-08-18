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

// Authenticate returns HTTP middleware that validates the session token
// from the channel(s) selected by the configured TokenSource (default
// TokenSourceBoth: either an Authorization: Bearer header or the
// configured session cookie — see WithTokenSource and WithCookieName).
// On success, the User and Session are attached to the request context
// and can be retrieved with UserFromContext and SessionFromContext.
// On failure, the middleware responds with 401 Unauthorized, carrying
// WWW-Authenticate and Cache-Control: no-store (see writeUnauthorized).
func (s *Sulis) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := s.extractToken(r)
		if token == "" {
			s.writeUnauthorized(w)
			return
		}

		session, user, err := s.ValidateSession(r.Context(), token)
		if err != nil {
			s.writeUnauthorized(w)
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, user)
		ctx = context.WithValue(ctx, sessionContextKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// writeUnauthorized writes the 401 response Authenticate returns on
// failure. WWW-Authenticate (RFC 7235 §4.1 / RFC 6750) names the scheme a
// Bearer-token client should retry with — sent regardless of TokenSource,
// since it's the conventional client-facing signal on a 401 even for a
// cookie-authenticated deployment. Cache-Control: no-store keeps a shared
// or browser cache from ever storing an authentication failure, or worse,
// a response accidentally produced for someone else's stale session.
func (s *Sulis) writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="sulis"`)
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
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

// extractToken reads the session token from whichever channel(s) s.cfg.
// TokenSource permits, in precedence order: a Bearer header is tried
// first, and — deliberately — never falls back to a cookie if a Bearer
// header was presented but didn't hold a token (e.g. malformed). Falling
// back would let an attacker who can inject an Authorization header, but
// not read cookies, probe for a valid cookie-based session by observing
// whether validation "recovers"; see
// TestAuthenticateBearerTakesPrecedenceOverCookie.
func (s *Sulis) extractToken(r *http.Request) string {
	if s.cfg.TokenSource != TokenSourceCookieOnly {
		if auth := r.Header.Get("Authorization"); auth != "" {
			if after, ok := strings.CutPrefix(auth, "Bearer "); ok {
				return strings.TrimSpace(after)
			}
		}
	}

	if s.cfg.TokenSource != TokenSourceBearerOnly {
		if cookie, err := r.Cookie(s.cfg.CookieName); err == nil {
			return cookie.Value
		}
	}

	return ""
}
