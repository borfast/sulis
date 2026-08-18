package sulis

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthenticateAttachesUserAndSession(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, session, sessionTok, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	var gotUser *User
	var gotSession *Session
	var userOK, sessionOK bool
	handler := s.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, userOK = UserFromContext(r.Context())
		gotSession, sessionOK = SessionFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+sessionTok)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if !userOK {
		t.Fatal("expected UserFromContext to return ok=true")
	}
	if !sessionOK {
		t.Fatal("expected SessionFromContext to return ok=true")
	}
	if gotUser.ID != user.ID {
		t.Fatalf("expected user ID %s, got %s", user.ID, gotUser.ID)
	}
	if gotSession.ID != session.ID {
		t.Fatalf("expected session ID %s, got %s", session.ID, gotSession.ID)
	}
}

func TestAuthenticateAcceptsSessionCookie(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	_, _, sessionTok, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	handler := s.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: defaultCookieName, Value: sessionTok})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

func TestAuthenticateRejectsMissingToken(t *testing.T) {
	s := newTestSulis()

	called := false
	handler := s.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
	if called {
		t.Fatal("expected handler not to be called")
	}
}

func TestAuthenticateRejectsInvalidToken(t *testing.T) {
	s := newTestSulis()

	called := false
	handler := s.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer garbage-invalid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
	if called {
		t.Fatal("expected handler not to be called")
	}
}

// TestAuthenticateBearerTakesPrecedenceOverCookie asserts that a presented
// Authorization: Bearer header is authoritative: an invalid bearer token
// must not fall back to a valid session cookie. Falling back would let an
// attacker who can inject an Authorization header (but not read cookies,
// e.g. via a header-only proxy misconfiguration) probe for the presence of
// a valid cookie-based session by observing whether validation "recovers".
func TestAuthenticateBearerTakesPrecedenceOverCookie(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	_, _, sessionTok, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	called := false
	handler := s.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: defaultCookieName, Value: sessionTok})
	req.Header.Set("Authorization", "Bearer garbage-invalid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 (bearer must take precedence, not fall back to cookie), got %d", rec.Code)
	}
	if called {
		t.Fatal("expected handler not to be called")
	}
}

// TestAuthenticateRejectsNonBearerAuthorizationEvenWithValidCookie is the
// fix-round-1 regression test for a gap in the "Bearer takes precedence"
// rule above: that rule only checked a well-formed "Bearer <token>" header.
// A non-empty Authorization header that ISN'T "Bearer ..." at all (e.g.
// "Basic xyz", a scheme this middleware never accepts) fell through
// strings.CutPrefix's failure to the cookie branch, silently authenticating
// via the ambient cookie. That is a real cross-site risk: an attacker's
// page — allowed by a permissive, credentialed CORS policy to set an
// arbitrary Authorization header on a cross-site fetch — could set any
// non-Bearer value and still ride the victim's cookie on a
// TokenSourceBoth route the developer mentally filed as "Bearer API, no
// CSRF needed." Any non-empty Authorization header now suppresses the
// cookie fallback entirely for that request: the request is treated as
// Bearer-only once a caller volunteers ANY Authorization header, and a
// malformed one is a straightforward 401, never a silent recovery via
// cookie. See the T507 (fix round 1) Decisions row in PROGRESS.md.
func TestAuthenticateRejectsNonBearerAuthorizationEvenWithValidCookie(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	_, _, sessionTok, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	handler := s.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, authHeader := range []string{"Basic xyz", "Bearer"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: defaultCookieName, Value: sessionTok})
		req.Header.Set("Authorization", authHeader)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("Authorization=%q: expected 401 (non-Bearer header must suppress cookie fallback), got %d", authHeader, rec.Code)
		}
	}
}

// TestAuthenticateAcceptsCookieWhenNoAuthorizationHeaderIsPresent pins the
// unchanged half of the fix above: a request that never sends an
// Authorization header at all — the ordinary cookie-only browser case —
// still authenticates via the cookie exactly as before.
func TestAuthenticateAcceptsCookieWhenNoAuthorizationHeaderIsPresent(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	_, _, sessionTok, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	handler := s.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: defaultCookieName, Value: sessionTok})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// TestAuthenticateRejectsMissingTokenSetsSecurityHeaders asserts the 401
// path advertises WWW-Authenticate (RFC 7235/6750 — tells a Bearer client
// what scheme to retry with) and Cache-Control: no-store (an auth failure,
// or a response accidentally produced for someone else's stale session,
// must never be cached).
func TestAuthenticateRejectsMissingTokenSetsSecurityHeaders(t *testing.T) {
	s := newTestSulis()

	handler := s.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("expected a WWW-Authenticate header on the 401 response")
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected Cache-Control: no-store, got %q", got)
	}
}

// TestAuthenticateRejectsInvalidTokenSetsSecurityHeaders is the same
// assertion on the other 401 branch (a token was presented but did not
// validate), so a future refactor that handles the two branches separately
// can't silently drop the headers from just one of them.
func TestAuthenticateRejectsInvalidTokenSetsSecurityHeaders(t *testing.T) {
	s := newTestSulis()

	handler := s.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer garbage-invalid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("expected a WWW-Authenticate header on the 401 response")
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected Cache-Control: no-store, got %q", got)
	}
}

// TestAuthenticateTokenSourceCookieOnlyRejectsBearer asserts that with
// WithTokenSource(TokenSourceCookieOnly), a Bearer header is not merely
// deprioritized but never consulted at all: a valid Bearer token alone is
// rejected.
func TestAuthenticateTokenSourceCookieOnlyRejectsBearer(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithTokenSource(TokenSourceCookieOnly))
	ctx := context.Background()

	_, _, sessionTok, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	called := false
	handler := s.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+sessionTok)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 (cookie-only must ignore Bearer), got %d", rec.Code)
	}
	if called {
		t.Fatal("expected handler not to be called")
	}
}

// TestAuthenticateTokenSourceCookieOnlyAcceptsCookie is the positive half
// of the same configuration: the cookie itself must still work.
func TestAuthenticateTokenSourceCookieOnlyAcceptsCookie(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithTokenSource(TokenSourceCookieOnly))
	ctx := context.Background()

	_, _, sessionTok, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	handler := s.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: defaultCookieName, Value: sessionTok})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

// TestAuthenticateTokenSourceBearerOnlyRejectsCookie is the mirror image:
// with WithTokenSource(TokenSourceBearerOnly), a valid session cookie alone
// must not authenticate the request.
func TestAuthenticateTokenSourceBearerOnlyRejectsCookie(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithTokenSource(TokenSourceBearerOnly))
	ctx := context.Background()

	_, _, sessionTok, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	called := false
	handler := s.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: defaultCookieName, Value: sessionTok})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 (bearer-only must ignore cookie), got %d", rec.Code)
	}
	if called {
		t.Fatal("expected handler not to be called")
	}
}

// TestAuthenticateTokenSourceBearerOnlyAcceptsBearer is the positive half:
// the Bearer header itself must still work.
func TestAuthenticateTokenSourceBearerOnlyAcceptsBearer(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithTokenSource(TokenSourceBearerOnly))
	ctx := context.Background()

	_, _, sessionTok, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	handler := s.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+sessionTok)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}
