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
	req.AddCookie(&http.Cookie{Name: "session", Value: sessionTok})
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
	req.AddCookie(&http.Cookie{Name: "session", Value: sessionTok})
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
