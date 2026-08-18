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
// first (unless TokenSourceCookieOnly is configured, in which case the
// Authorization header is never even inspected — an explicit developer
// opt-out of the whole channel, not the ambiguous case this comment is
// about).
//
// Whenever the Authorization header IS inspected, presenting ANY non-empty
// value suppresses the cookie fallback entirely for that request — the
// request is treated as Bearer-only the moment a caller volunteers an
// Authorization header, whether or not it parses as "Bearer <token>". A
// well-formed "Bearer <token>" returns that token; anything else (missing
// the "Bearer " prefix, a different scheme like "Basic ...", or malformed
// in any other way) returns "" immediately, never falling through to the
// cookie. Falling through on a malformed-but-present header would let an
// attacker who can make the browser send an arbitrary Authorization value
// on a cross-site request — a credentialed CORS misconfiguration is a
// realistic way to get exactly that — but can't read cookies directly,
// still ride the victim's ambient cookie on a route the developer may have
// filed as "Bearer API, no CSRF needed" specifically because it inspects
// Authorization at all. A client that sends a non-Bearer Authorization
// header on a request it also expects cookie auth to satisfy was never a
// sane configuration to support; see
// TestAuthenticateBearerTakesPrecedenceOverCookie and
// TestAuthenticateRejectsNonBearerAuthorizationEvenWithValidCookie, and the
// T507 (fix round 1) Decisions row in PROGRESS.md.
func (s *Sulis) extractToken(r *http.Request) string {
	if s.cfg.TokenSource != TokenSourceCookieOnly {
		if auth := r.Header.Get("Authorization"); auth != "" {
			after, ok := strings.CutPrefix(auth, "Bearer ")
			if !ok {
				return ""
			}
			return strings.TrimSpace(after)
		}
	}

	if s.cfg.TokenSource != TokenSourceBearerOnly {
		if cookie, err := r.Cookie(s.cfg.CookieName); err == nil {
			return cookie.Value
		}
	}

	return ""
}
