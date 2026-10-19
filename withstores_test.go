package sulis

import (
	"context"
	"errors"
	"testing"
)

func TestWithStoresUsesTheNewStores(t *testing.T) {
	ctx := context.Background()
	s, usersA, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	usersB, sessionsB := newMemUserStore(), newMemSessionStore()
	c, err := s.WithStores(usersB, sessionsB, newMemTokenStore(), NoSecondFactors{})
	if err != nil {
		t.Fatalf("WithStores: %v", err)
	}

	user, _, token, err := c.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register on the copy: %v", err)
	}
	if _, err := usersB.GetUserByID(ctx, user.ID); err != nil {
		t.Errorf("new user store: GetUserByID = %v, want the user", err)
	}
	if _, err := usersA.GetUserByID(ctx, user.ID); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("original user store: GetUserByID = %v, want ErrUserNotFound", err)
	}
	if got, err := sessionsB.ListUserSessions(ctx, user.ID); err != nil || len(got) != 1 {
		t.Errorf("new session store: ListUserSessions = %d sessions, %v; want 1", len(got), err)
	}
	if _, _, err := c.ValidateSession(ctx, token); err != nil {
		t.Errorf("copy: ValidateSession = %v, want the session", err)
	}
	if _, _, err := s.ValidateSession(ctx, token); err == nil {
		t.Error("original: ValidateSession accepted a session held only by the copy's store")
	}
}

func TestWithStoresUsesTheNewTokensAndFactors(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithRequireVerifiedEmail(false))
	tokensB, factorsB := newMemTokenStore(), newFakeFactors()
	c, err := s.WithStores(newMemUserStore(), newMemSessionStore(), tokensB, factorsB)
	if err != nil {
		t.Fatalf("WithStores: %v", err)
	}
	user, _, _, err := c.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register on the copy: %v", err)
	}

	if _, err := c.CreateEmailVerificationToken(ctx, user.ID); err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}
	if len(tokensB.tokens) != 1 {
		t.Errorf("new token store holds %d tokens, want 1", len(tokensB.tokens))
	}

	factorsB.enroll(user.ID)
	res, err := c.Login(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil || !res.NeedsSecondFactor {
		t.Errorf("Login = %+v, %v; want NeedsSecondFactor from the new checker", res, err)
	}
}

func TestWithStoresSharesEverythingElse(t *testing.T) {
	ctx := context.Background()
	limiter, sink := &fakeLimiter{}, &recordingSink{}
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithLimiter(limiter), WithEventSink(sink))
	c, err := s.WithStores(newMemUserStore(), newMemSessionStore(), newMemTokenStore(), NoSecondFactors{})
	if err != nil {
		t.Fatalf("WithStores: %v", err)
	}
	// A different dummy hash would mean the copy paid for its own Argon2 hash.
	if c.dummyHash != s.dummyHash {
		t.Error("the copy computed its own dummy hash")
	}

	if _, err := c.VerifyPassword(ctx, "nobody@example.com", "wrong-password", RequestInfo{}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("VerifyPassword = %v, want ErrInvalidCredentials", err)
	}
	if len(limiter.keys) == 0 {
		t.Error("the copy did not consult the original's limiter")
	}
	if len(sink.all()) == 0 {
		t.Error("the copy did not emit to the original's event sink")
	}
}

func TestWithStoresRefusesNilStores(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	users, sessions, tokens := newMemUserStore(), newMemSessionStore(), newMemTokenStore()
	calls := map[string]func() (*Sulis, error){
		"users":    func() (*Sulis, error) { return s.WithStores(nil, sessions, tokens, NoSecondFactors{}) },
		"sessions": func() (*Sulis, error) { return s.WithStores(users, nil, tokens, NoSecondFactors{}) },
		"tokens":   func() (*Sulis, error) { return s.WithStores(users, sessions, nil, NoSecondFactors{}) },
		"factors":  func() (*Sulis, error) { return s.WithStores(users, sessions, tokens, nil) },
	}
	for name, call := range calls {
		if c, err := call(); err == nil || c != nil {
			t.Errorf("nil %s: WithStores = %v, %v; want nil and an error", name, c, err)
		}
	}
}
