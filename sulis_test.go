package sulis

import (
	"context"
	"errors"
	"fmt"
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

func (s *memSessionStore) GetSessionByTokenHash(_ context.Context, tokenHash string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessions {
		if sess.TokenHash == tokenHash {
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
	return nil, ErrTokenNotFound
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
	if sess.Token != session.Token {
		t.Fatal("validated session should preserve the presented raw token")
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

type observingSessionStore struct {
	mu              sync.Mutex
	created         *Session
	sessionByHash   map[string]*Session
	lookupTokenHash string
	lookupErr       error
}

func newObservingSessionStore() *observingSessionStore {
	return &observingSessionStore{sessionByHash: make(map[string]*Session)}
}

func (s *observingSessionStore) CreateSession(_ context.Context, sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *sess
	s.created = &cp
	s.sessionByHash[sess.TokenHash] = &cp
	return nil
}

func (s *observingSessionStore) GetSessionByTokenHash(_ context.Context, tokenHash string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lookupTokenHash = tokenHash
	if s.lookupErr != nil {
		return nil, s.lookupErr
	}
	sess, ok := s.sessionByHash[tokenHash]
	if !ok {
		return nil, ErrSessionNotFound
	}
	cp := *sess
	return &cp, nil
}

func (s *observingSessionStore) DeleteSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, sess := range s.sessionByHash {
		if sess.ID == id {
			delete(s.sessionByHash, hash)
		}
	}
	return nil
}

func (s *observingSessionStore) DeleteUserSessions(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, sess := range s.sessionByHash {
		if sess.UserID == userID {
			delete(s.sessionByHash, hash)
		}
	}
	return nil
}

func (s *observingSessionStore) CleanExpired(_ context.Context) error {
	return nil
}

type sharedSessionStore struct {
	session *Session
}

func (s *sharedSessionStore) CreateSession(_ context.Context, sess *Session) error {
	s.session = sess
	return nil
}

func (s *sharedSessionStore) GetSessionByTokenHash(_ context.Context, tokenHash string) (*Session, error) {
	if s.session == nil || s.session.TokenHash != tokenHash {
		return nil, ErrSessionNotFound
	}
	return s.session, nil
}

func (s *sharedSessionStore) DeleteSession(_ context.Context, _ string) error { return nil }

func (s *sharedSessionStore) DeleteUserSessions(_ context.Context, _ string) error { return nil }

func (s *sharedSessionStore) CleanExpired(_ context.Context) error { return nil }

type errTokenStore struct {
	err error
}

func (s *errTokenStore) CreateToken(_ context.Context, _ *Token) error { return nil }

func (s *errTokenStore) GetTokenByHash(_ context.Context, _ string) (*Token, error) {
	return nil, s.err
}

func (s *errTokenStore) MarkTokenUsed(_ context.Context, _ string) error { return nil }

func (s *errTokenStore) DeleteExpiredTokens(_ context.Context) error { return nil }

type wrappedNotFoundUserStore struct {
	mu   sync.Mutex
	user *User
}

func (s *wrappedNotFoundUserStore) CreateUser(_ context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *user
	s.user = &cp
	return nil
}

func (s *wrappedNotFoundUserStore) GetUserByID(_ context.Context, id string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.user != nil && s.user.ID == id {
		cp := *s.user
		return &cp, nil
	}
	return nil, ErrUserNotFound
}

func (s *wrappedNotFoundUserStore) GetUserByEmail(_ context.Context, email string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.user != nil && s.user.Email == email {
		cp := *s.user
		return &cp, nil
	}
	return nil, fmt.Errorf("wrapped lookup failure: %w", ErrUserNotFound)
}

func (s *wrappedNotFoundUserStore) UpdateUser(_ context.Context, _ *User) error { return nil }

func (s *wrappedNotFoundUserStore) DeleteUser(_ context.Context, _ string) error { return nil }

func TestCreateSessionStoresOnlyTokenHash(t *testing.T) {
	ctx := context.Background()
	users := newMemUserStore()
	sessions := newObservingSessionStore()
	s := New(users, sessions, newMemTokenStore())

	user, session, err := s.Register(ctx, "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if user.ID == "" {
		t.Fatal("expected created user")
	}
	if session.Token == "" {
		t.Fatal("expected issued session to include raw token")
	}
	if session.TokenHash == "" {
		t.Fatal("expected issued session to include token hash")
	}
	if session.TokenHash != hashSessionToken(session.Token) {
		t.Fatal("expected issued session token hash to match raw token")
	}
	if sessions.created == nil {
		t.Fatal("expected session store create call")
	}
	if sessions.created.Token != "" {
		t.Fatalf("expected persisted session token to be blank, got %q", sessions.created.Token)
	}
	if sessions.created.TokenHash != session.TokenHash {
		t.Fatal("expected persisted session to store token hash")
	}
}

func TestValidateSessionLooksUpByTokenHash(t *testing.T) {
	ctx := context.Background()
	users := newMemUserStore()
	sessions := newObservingSessionStore()
	s := New(users, sessions, newMemTokenStore())

	_, err := users.GetUserByEmail(ctx, "alice@example.com")
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected empty store to miss user, got %v", err)
	}

	createdUser := &User{ID: "user-1", Email: "alice@example.com", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := users.CreateUser(ctx, createdUser); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	rawToken := "raw-session-token"
	hash := hashSessionToken(rawToken)
	sessions.sessionByHash[hash] = &Session{
		ID:        "session-1",
		UserID:    createdUser.ID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}

	session, gotUser, err := s.ValidateSession(ctx, rawToken)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if session.ID != "session-1" {
		t.Fatalf("expected session-1, got %s", session.ID)
	}
	if gotUser.ID != createdUser.ID {
		t.Fatalf("expected user %s, got %s", createdUser.ID, gotUser.ID)
	}
	if sessions.lookupTokenHash != hash {
		t.Fatalf("expected lookup by hashed token %q, got %q", hash, sessions.lookupTokenHash)
	}
}

func TestValidateSessionDoesNotMutateStoredSession(t *testing.T) {
	ctx := context.Background()
	users := newMemUserStore()
	store := &sharedSessionStore{}
	s := New(users, store, newMemTokenStore())

	createdUser := &User{ID: "user-1", Email: "alice@example.com", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := users.CreateUser(ctx, createdUser); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	rawToken := "raw-session-token"
	store.session = &Session{
		ID:        "session-1",
		UserID:    createdUser.ID,
		TokenHash: hashSessionToken(rawToken),
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}

	validated, _, err := s.ValidateSession(ctx, rawToken)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if validated.Token != rawToken {
		t.Fatalf("expected validated session token %q, got %q", rawToken, validated.Token)
	}
	if store.session.Token != "" {
		t.Fatalf("expected stored session token to remain blank, got %q", store.session.Token)
	}
}

func TestChangePasswordRejectsPasswordlessUser(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	if _, err := s.CreateMagicLinkToken(ctx, "bob@example.com"); err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	user, err := s.users.GetUserByEmail(ctx, "bob@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}

	err = s.ChangePassword(ctx, user.ID, "", "new-password")
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestSetInitialPassword(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	if _, err := s.CreateMagicLinkToken(ctx, "bob@example.com"); err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	user, err := s.users.GetUserByEmail(ctx, "bob@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if user.PasswordHash != "" {
		t.Fatal("expected passwordless user")
	}

	if err := s.SetInitialPassword(ctx, user.ID, "new-password"); err != nil {
		t.Fatalf("SetInitialPassword: %v", err)
	}

	_, _, err = s.Login(ctx, "bob@example.com", "new-password")
	if err != nil {
		t.Fatalf("Login with initial password: %v", err)
	}
}

func TestSetInitialPasswordRejectsExistingPassword(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	user, _, err := s.Register(ctx, "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	err = s.SetInitialPassword(ctx, user.ID, "new-password")
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestValidateTokenPropagatesLookupFailures(t *testing.T) {
	ctx := context.Background()
	wantErr := errors.New("token store offline")
	s := New(newMemUserStore(), newMemSessionStore(), &errTokenStore{err: wantErr})

	_, err := s.validateToken(ctx, "raw-token", TokenPurposeMagicLink)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected lookup error to propagate, got %v", err)
	}
}

func TestValidateTokenNormalizesWrappedTokenNotFound(t *testing.T) {
	ctx := context.Background()
	s := New(
		newMemUserStore(),
		newMemSessionStore(),
		&errTokenStore{err: fmt.Errorf("wrapped token lookup: %w", ErrTokenNotFound)},
	)

	_, err := s.validateToken(ctx, "raw-token", TokenPurposeMagicLink)
	if err != ErrTokenInvalid {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestCreateMagicLinkTokenAcceptsWrappedUserNotFound(t *testing.T) {
	ctx := context.Background()
	s := New(&wrappedNotFoundUserStore{}, newMemSessionStore(), newMemTokenStore())

	rawToken, err := s.CreateMagicLinkToken(ctx, "wrapped@example.com")
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	if rawToken == "" {
		t.Fatal("expected magic link token")
	}
}
