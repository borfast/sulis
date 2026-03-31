package sulis

import (
	"context"
	"sync"
	"testing"
	"time"
)

// In-memory store implementations for testing.

type memUserStore struct {
	mu    sync.Mutex
	users map[string]*User
}

func newMemUserStore() *memUserStore {
	return &memUserStore{users: make(map[string]*User)}
}

func (s *memUserStore) CreateUser(_ context.Context, u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.users {
		if existing.Email == u.Email {
			return ErrUserAlreadyExists
		}
	}
	cp := *u
	s.users[u.ID] = &cp
	return nil
}

func (s *memUserStore) GetUserByID(_ context.Context, id string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return nil, ErrUserNotFound
	}
	cp := *u
	return &cp, nil
}

func (s *memUserStore) GetUserByEmail(_ context.Context, email string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.Email == email {
			cp := *u
			return &cp, nil
		}
	}
	return nil, ErrUserNotFound
}

func (s *memUserStore) UpdateUser(_ context.Context, u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[u.ID]; !ok {
		return ErrUserNotFound
	}
	cp := *u
	s.users[u.ID] = &cp
	return nil
}

func (s *memUserStore) DeleteUser(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, id)
	return nil
}

type memSessionStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

func newMemSessionStore() *memSessionStore {
	return &memSessionStore{sessions: make(map[string]*Session)}
}

func (s *memSessionStore) CreateSession(_ context.Context, sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *sess
	s.sessions[sess.ID] = &cp
	return nil
}

func (s *memSessionStore) GetSessionByToken(_ context.Context, token string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessions {
		if sess.Token == token {
			cp := *sess
			return &cp, nil
		}
	}
	return nil, ErrSessionNotFound
}

func (s *memSessionStore) DeleteSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}

func (s *memSessionStore) DeleteUserSessions(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.UserID == userID {
			delete(s.sessions, id)
		}
	}
	return nil
}

func (s *memSessionStore) CleanExpired(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
	return nil
}

type memTokenStore struct {
	mu     sync.Mutex
	tokens map[string]*Token
}

func newMemTokenStore() *memTokenStore {
	return &memTokenStore{tokens: make(map[string]*Token)}
}

func (s *memTokenStore) CreateToken(_ context.Context, t *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *t
	s.tokens[t.ID] = &cp
	return nil
}

func (s *memTokenStore) GetTokenByHash(_ context.Context, hash string) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tokens {
		if t.TokenHash == hash {
			cp := *t
			return &cp, nil
		}
	}
	return nil, ErrTokenInvalid
}

func (s *memTokenStore) MarkTokenUsed(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok {
		return ErrTokenInvalid
	}
	t.Used = true
	return nil
}

func (s *memTokenStore) DeleteExpiredTokens(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, t := range s.tokens {
		if now.After(t.ExpiresAt) {
			delete(s.tokens, id)
		}
	}
	return nil
}

func newTestSulis() *Sulis {
	return New(
		newMemUserStore(),
		newMemSessionStore(),
		newMemTokenStore(),
	)
}

func TestRegisterAndLogin(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	user, session, err := s.Register(ctx, "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if user.Email != "alice@example.com" {
		t.Fatalf("expected email alice@example.com, got %s", user.Email)
	}
	if session.Token == "" {
		t.Fatal("expected non-empty session token")
	}

	// Login with correct credentials.
	user2, session2, err := s.Login(ctx, "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if user2.ID != user.ID {
		t.Fatal("login returned different user ID")
	}
	if session2.Token == session.Token {
		t.Fatal("login should create a new session token")
	}

	// Login with wrong password.
	_, _, err = s.Login(ctx, "alice@example.com", "wrong")
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	// Login with non-existent user.
	_, _, err = s.Login(ctx, "nobody@example.com", "password123")
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestRegisterDuplicate(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	_, _, err := s.Register(ctx, "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	_, _, err = s.Register(ctx, "alice@example.com", "password456")
	if err != ErrUserAlreadyExists {
		t.Fatalf("expected ErrUserAlreadyExists, got %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	user, _, _ := s.Register(ctx, "alice@example.com", "old-password")

	err := s.ChangePassword(ctx, user.ID, "old-password", "new-password")
	if err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	// Old password should no longer work.
	_, _, err = s.Login(ctx, "alice@example.com", "old-password")
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials with old password, got %v", err)
	}

	// New password should work.
	_, _, err = s.Login(ctx, "alice@example.com", "new-password")
	if err != nil {
		t.Fatalf("Login with new password: %v", err)
	}
}

func TestValidateAndRevokeSession(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	_, session, _ := s.Register(ctx, "alice@example.com", "password123")

	// Validate the session.
	sess, user, err := s.ValidateSession(ctx, session.Token)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if user.Email != "alice@example.com" {
		t.Fatal("wrong user from session")
	}

	// Revoke the session.
	if err := s.RevokeSession(ctx, sess.ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}

	// Session should no longer be valid.
	_, _, err = s.ValidateSession(ctx, session.Token)
	if err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound after revoke, got %v", err)
	}
}

func TestPasswordResetFlow(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	s.Register(ctx, "alice@example.com", "old-password")

	rawToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	err = s.ResetPassword(ctx, rawToken, "new-password")
	if err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	// Old password should no longer work.
	_, _, err = s.Login(ctx, "alice@example.com", "old-password")
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	// New password should work.
	_, _, err = s.Login(ctx, "alice@example.com", "new-password")
	if err != nil {
		t.Fatalf("Login with reset password: %v", err)
	}

	// Token should be used; can't reuse.
	err = s.ResetPassword(ctx, rawToken, "another-password")
	if err != ErrTokenAlreadyUsed {
		t.Fatalf("expected ErrTokenAlreadyUsed, got %v", err)
	}
}

func TestMagicLinkFlow(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	// Magic link for new user (should auto-create).
	rawToken, err := s.CreateMagicLinkToken(ctx, "bob@example.com")
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	user, session, err := s.RedeemMagicLink(ctx, rawToken)
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	if user.Email != "bob@example.com" {
		t.Fatalf("expected bob@example.com, got %s", user.Email)
	}
	if session.Token == "" {
		t.Fatal("expected non-empty session token")
	}
	if user.PasswordHash != "" {
		t.Fatal("magic link user should have no password hash")
	}

	// Token should be used; can't reuse.
	_, _, err = s.RedeemMagicLink(ctx, rawToken)
	if err != ErrTokenAlreadyUsed {
		t.Fatalf("expected ErrTokenAlreadyUsed, got %v", err)
	}
}
