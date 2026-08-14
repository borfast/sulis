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

func (s *memTokenStore) ConsumeToken(_ context.Context, hash string, purpose TokenPurpose) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tokens {
		if t.TokenHash == hash && t.Purpose == purpose {
			if t.Used {
				return nil, ErrTokenAlreadyUsed
			}
			t.Used = true
			cp := *t
			return &cp, nil
		}
	}
	return nil, ErrTokenNotFound
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

func (s *memTokenStore) DeleteUserTokens(_ context.Context, userID string, purpose TokenPurpose) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, t := range s.tokens {
		if t.UserID == userID && t.Purpose == purpose {
			delete(s.tokens, id)
		}
	}
	return nil
}

// newTestEnv builds a Sulis instance wired to fresh in-memory stores and
// returns the stores alongside it so tests can inspect persisted state directly.
func newTestEnv(opts ...Option) (*Sulis, *memUserStore, *memSessionStore, *memTokenStore) {
	users := newMemUserStore()
	sessions := newMemSessionStore()
	tokens := newMemTokenStore()
	s := New(users, sessions, tokens, opts...)
	return s, users, sessions, tokens
}

func newTestSulis() *Sulis {
	s, _, _, _ := newTestEnv()
	return s
}

// testArgon2Params are deliberately weak, fast Argon2 parameters for tests
// that exercise password hashing but aren't testing timing behavior itself.
var testArgon2Params = Argon2Params{
	Memory:      8 * 1024,
	Iterations:  1,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
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

	// Token should be used and deleted by the outstanding-token cleanup; can't reuse.
	err = s.ResetPassword(ctx, rawToken, "another-password")
	if err != ErrTokenInvalid {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
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

func (s *errTokenStore) ConsumeToken(_ context.Context, _ string, _ TokenPurpose) (*Token, error) {
	return nil, s.err
}

func (s *errTokenStore) DeleteExpiredTokens(_ context.Context) error { return nil }

func (s *errTokenStore) DeleteUserTokens(_ context.Context, _ string, _ TokenPurpose) error {
	return nil
}

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

// failUpdateUserStore wraps a real memUserStore but forces UpdateUser to fail,
// so tests can assert token consumption happens before the password change.
type failUpdateUserStore struct {
	*memUserStore
	updateErr error
}

func (s *failUpdateUserStore) UpdateUser(_ context.Context, _ *User) error {
	return s.updateErr
}

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
	if validated.Token != "" {
		t.Fatalf("expected validated session token to be blank, got %q", validated.Token)
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

func TestConsumeTokenPropagatesLookupFailures(t *testing.T) {
	ctx := context.Background()
	wantErr := errors.New("token store offline")
	s := New(newMemUserStore(), newMemSessionStore(), &errTokenStore{err: wantErr})

	_, err := s.consumeToken(ctx, "raw-token", TokenPurposeMagicLink)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected lookup error to propagate, got %v", err)
	}
}

func TestConsumeTokenNormalizesWrappedTokenNotFound(t *testing.T) {
	ctx := context.Background()
	s := New(
		newMemUserStore(),
		newMemSessionStore(),
		&errTokenStore{err: fmt.Errorf("wrapped token lookup: %w", ErrTokenNotFound)},
	)

	_, err := s.consumeToken(ctx, "raw-token", TokenPurposeMagicLink)
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

func TestResetPasswordConsumesTokenBeforePasswordChange(t *testing.T) {
	ctx := context.Background()
	updateErr := errors.New("update user failed")
	users := &failUpdateUserStore{memUserStore: newMemUserStore(), updateErr: updateErr}
	s := New(users, newMemSessionStore(), newMemTokenStore())

	if _, _, err := s.Register(ctx, "alice@example.com", "old-password"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	rawToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	err = s.ResetPassword(ctx, rawToken, "new-password")
	if !errors.Is(err, updateErr) {
		t.Fatalf("expected update error, got %v", err)
	}

	// The token must already be consumed even though the password change
	// failed, so a second attempt with the same raw token is rejected.
	err = s.ResetPassword(ctx, rawToken, "another-password")
	if err != ErrTokenAlreadyUsed {
		t.Fatalf("expected ErrTokenAlreadyUsed, got %v", err)
	}
}

func TestConcurrentResetPasswordSingleWinner(t *testing.T) {
	ctx := context.Background()
	s := newTestSulis()

	if _, _, err := s.Register(ctx, "alice@example.com", "old-password"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	rawToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = s.ResetPassword(ctx, rawToken, fmt.Sprintf("new-password-%d", i))
		}(i)
	}
	wg.Wait()

	var nilCount, usedCount int
	for _, e := range errs {
		switch {
		case e == nil:
			nilCount++
		case errors.Is(e, ErrTokenAlreadyUsed):
			usedCount++
		default:
			t.Fatalf("unexpected error: %v", e)
		}
	}
	if nilCount != 1 || usedCount != 1 {
		t.Fatalf("expected exactly one success and one already-used, got nilCount=%d usedCount=%d", nilCount, usedCount)
	}
}

func TestConsumeTokenWrongPurposeIsInvalid(t *testing.T) {
	ctx := context.Background()
	s := newTestSulis()

	if _, _, err := s.Register(ctx, "alice@example.com", "old-password"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	rawToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	// Presenting a reset token to the magic-link flow must not consume it.
	_, _, err = s.RedeemMagicLink(ctx, rawToken)
	if err != ErrTokenInvalid {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}

	// The token must still be usable for its original purpose.
	err = s.ResetPassword(ctx, rawToken, "new-password")
	if err != nil {
		t.Fatalf("expected reset token to remain usable, got %v", err)
	}
}

func TestResetPasswordRevokesAllSessions(t *testing.T) {
	s, _, sessions, _ := newTestEnv()
	ctx := context.Background()

	_, session, err := s.Register(ctx, "alice@example.com", "old-password")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	rawToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	if err := s.ResetPassword(ctx, rawToken, "new-password"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	// The pre-reset session must be invalidated.
	if _, _, err := s.ValidateSession(ctx, session.Token); err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound for pre-reset session, got %v", err)
	}
	if len(sessions.sessions) != 0 {
		t.Fatalf("expected all sessions revoked, got %d remaining", len(sessions.sessions))
	}
}

func TestChangePasswordRevokesAllSessions(t *testing.T) {
	s, _, sessions, _ := newTestEnv()
	ctx := context.Background()

	user, session, err := s.Register(ctx, "alice@example.com", "old-password")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := s.ChangePassword(ctx, user.ID, "old-password", "new-password"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	// The pre-change session must be invalidated.
	if _, _, err := s.ValidateSession(ctx, session.Token); err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound for pre-change session, got %v", err)
	}
	if len(sessions.sessions) != 0 {
		t.Fatalf("expected all sessions revoked, got %d remaining", len(sessions.sessions))
	}
}

func TestResetPasswordDeletesOutstandingResetTokens(t *testing.T) {
	s, _, _, tokens := newTestEnv()
	ctx := context.Background()

	if _, _, err := s.Register(ctx, "alice@example.com", "old-password"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	firstToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("CreatePasswordResetToken (first): %v", err)
	}
	secondToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("CreatePasswordResetToken (second): %v", err)
	}

	if err := s.ResetPassword(ctx, firstToken, "new-password"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	// The second, still-live reset token must no longer be redeemable.
	if err := s.ResetPassword(ctx, secondToken, "another-password"); err != ErrTokenInvalid {
		t.Fatalf("expected ErrTokenInvalid for outstanding reset token, got %v", err)
	}
	if len(tokens.tokens) != 0 {
		t.Fatalf("expected outstanding reset tokens deleted, got %d remaining", len(tokens.tokens))
	}
}

func TestWithRevokeSessionsOnPasswordChangeFalseKeepsSessions(t *testing.T) {
	s, _, sessions, tokens := newTestEnv(WithRevokeSessionsOnPasswordChange(false))
	ctx := context.Background()

	_, session, err := s.Register(ctx, "alice@example.com", "old-password")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	rawToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	if err := s.ResetPassword(ctx, rawToken, "new-password"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	// Session revocation opted out: the pre-reset session should still validate.
	if _, _, err := s.ValidateSession(ctx, session.Token); err != nil {
		t.Fatalf("expected session to remain valid, got %v", err)
	}
	if len(sessions.sessions) != 1 {
		t.Fatalf("expected session to survive, got %d remaining", len(sessions.sessions))
	}

	// DeleteUserTokens still runs unconditionally even when session revocation is skipped.
	if len(tokens.tokens) != 0 {
		t.Fatalf("expected reset tokens still deleted, got %d remaining", len(tokens.tokens))
	}
}

func TestValidateSessionDoesNotEchoRawToken(t *testing.T) {
	s, _, _, _ := newTestEnv()
	ctx := context.Background()

	_, session, err := s.Register(ctx, "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	validated, _, err := s.ValidateSession(ctx, session.Token)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if validated.Token != "" {
		t.Fatalf("expected validated session token to be blank, got %q", validated.Token)
	}
}

// TestLoginUnknownUserStillRunsArgon2 asserts that Login for an unknown email
// pays roughly the same Argon2 cost as a known email with a wrong password,
// so response timing doesn't reveal whether an account exists. This must use
// the DEFAULT (slow) Argon2 params for the comparison to be meaningful.
func TestLoginUnknownUserStillRunsArgon2(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	if _, _, err := s.Register(ctx, "alice@example.com", "correct-password"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	const iterations = 3
	var knownTotal, unknownTotal time.Duration

	for i := 0; i < iterations; i++ {
		start := time.Now()
		if _, _, err := s.Login(ctx, "alice@example.com", "wrong-password"); err != ErrInvalidCredentials {
			t.Fatalf("expected ErrInvalidCredentials for wrong password, got %v", err)
		}
		knownTotal += time.Since(start)

		start = time.Now()
		if _, _, err := s.Login(ctx, "nobody@example.com", "wrong-password"); err != ErrInvalidCredentials {
			t.Fatalf("expected ErrInvalidCredentials for unknown email, got %v", err)
		}
		unknownTotal += time.Since(start)
	}

	knownAvg := knownTotal / iterations
	unknownAvg := unknownTotal / iterations

	// Coarse bound (not a precise statistical test): an unknown-email login
	// must still pay at least half of the Argon2 cost a known-email
	// wrong-password login pays. A near-zero unknownAvg would indicate the
	// early-return path is skipping password verification entirely.
	if unknownAvg < knownAvg/2 {
		t.Fatalf("unknown-email login too fast, timing leaks account existence: known avg=%v unknown avg=%v", knownAvg, unknownAvg)
	}
}

// TestLoginPasswordlessUserReturnsInvalidCredentials documents that a
// passwordless (magic-link-only) user still gets ErrInvalidCredentials on a
// password login attempt, now via a dummy verify rather than an early return.
func TestLoginPasswordlessUserReturnsInvalidCredentials(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	if _, err := s.CreateMagicLinkToken(ctx, "bob@example.com"); err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	if _, _, err := s.Login(ctx, "bob@example.com", "any-password"); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}
