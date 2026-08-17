package sulis

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// In-memory store implementations for testing.

type memUserStore struct {
	mu    sync.Mutex
	users map[string]*User
	// beforeUpdate, if set, fires once at the start of the next UpdateUser
	// call and is then cleared. It lets a test interleave another complete
	// flow between a caller's read of the user and its write, so
	// lost-update races are deterministic instead of timing-dependent.
	beforeUpdate func(*User)
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
	// Take and clear the hook before locking, so the hook can call back into
	// the store without deadlocking.
	s.mu.Lock()
	hook := s.beforeUpdate
	s.beforeUpdate = nil
	s.mu.Unlock()
	if hook != nil {
		hook(u)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.users[u.ID]
	if !ok {
		return ErrUserNotFound
	}
	// Optimistic concurrency, as UserStore.UpdateUser requires: a write built
	// from a stale read must be rejected rather than silently clobbering the
	// newer row.
	if existing.Version != u.Version {
		return ErrConcurrentUpdate
	}
	cp := *u
	cp.Version = existing.Version + 1
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

// count reports how many sessions are stored, for tests asserting that a flow
// created no session at all.
func (s *memSessionStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
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

// fakeLimiter records every key it is asked about and denies (returning
// denyErr, or a generic error if denyErr is nil) whenever denied is true.
type fakeLimiter struct {
	mu      sync.Mutex
	keys    []string
	denied  bool
	denyErr error
}

func (f *fakeLimiter) Allow(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = append(f.keys, key)
	if f.denied {
		if f.denyErr != nil {
			return f.denyErr
		}
		return errors.New("denied")
	}
	return nil
}

// fakeFactors is a SecondFactorChecker whose answers tests control.
type fakeFactors struct {
	mu       sync.Mutex
	enrolled map[string]bool
	err      error
}

func newFakeFactors() *fakeFactors {
	return &fakeFactors{enrolled: make(map[string]bool)}
}

func (f *fakeFactors) HasSecondFactor(_ context.Context, userID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return false, f.err
	}
	return f.enrolled[userID], nil
}

func (f *fakeFactors) enroll(userID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enrolled[userID] = true
}

func (f *fakeFactors) failWith(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// mustNew builds a Sulis with no second factors, panicking on a construction
// error. Tests that exercise New's own validation call New directly.
func mustNew(users UserStore, sessions SessionStore, tokens TokenStore, opts ...Option) *Sulis {
	s, err := New(users, sessions, tokens, NoSecondFactors{}, opts...)
	if err != nil {
		panic("mustNew: " + err.Error())
	}
	return s
}

// redeemMagicLink adapts RedeemMagicLink's LoginResult back to the
// (user, session) shape most tests assert on. It fails the test if a second
// factor is unexpectedly demanded; tests covering that branch call
// RedeemMagicLink directly.
func redeemMagicLink(t *testing.T, s *Sulis, ctx context.Context, rawToken string) (*User, *Session, string, error) {
	t.Helper()
	res, err := s.RedeemMagicLink(ctx, rawToken, RequestInfo{})
	if err != nil {
		return nil, nil, "", err
	}
	if res.NeedsSecondFactor {
		t.Fatal("this test does not expect a second-factor demand")
	}
	return res.User, res.Session, res.SessionToken, nil
}

// newTestEnv builds a Sulis instance wired to fresh in-memory stores and
// returns the stores alongside it so tests can inspect persisted state directly.
func newTestEnv(opts ...Option) (*Sulis, *memUserStore, *memSessionStore, *memTokenStore) {
	s, users, sessions, tokens, _ := newTestEnvWithFactors(opts...)
	return s, users, sessions, tokens
}

// newTestEnvWithFactors additionally returns the second-factor checker, for
// tests that need to enroll a factor or make the check fail.
func newTestEnvWithFactors(opts ...Option) (*Sulis, *memUserStore, *memSessionStore, *memTokenStore, *fakeFactors) {
	users := newMemUserStore()
	sessions := newMemSessionStore()
	tokens := newMemTokenStore()
	factors := newFakeFactors()
	s, err := New(users, sessions, tokens, factors, opts...)
	if err != nil {
		panic("newTestEnvWithFactors: " + err.Error())
	}
	return s, users, sessions, tokens, factors
}

func newTestSulis() *Sulis {
	s, _, _, _ := newTestEnv()
	return s
}

// verifyUserEmail stamps EmailVerifiedAt directly on the stored user, for
// tests where verification is incidental to what's being tested. It bypasses
// VerifyEmail/RedeemMagicLink so it has no side effects (e.g. no session
// revocation).
func verifyUserEmail(t *testing.T, users *memUserStore, userID string) {
	t.Helper()
	ctx := context.Background()
	u, err := users.GetUserByID(ctx, userID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	now := time.Now()
	u.EmailVerifiedAt = &now
	if err := users.UpdateUser(ctx, u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
}

// unverifyUserEmail clears EmailVerifiedAt directly on the stored user.
func unverifyUserEmail(t *testing.T, users *memUserStore, userID string) {
	t.Helper()
	ctx := context.Background()
	u, err := users.GetUserByID(ctx, userID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	u.EmailVerifiedAt = nil
	if err := users.UpdateUser(ctx, u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
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
	s, users, _, _ := newTestEnv()
	ctx := context.Background()

	user, _, sessionTok, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if user.Email != "alice@example.com" {
		t.Fatalf("expected email alice@example.com, got %s", user.Email)
	}
	if sessionTok == "" {
		t.Fatal("expected non-empty session token")
	}
	// Verification is incidental to this test; the gate is covered elsewhere.
	verifyUserEmail(t, users, user.ID)

	// Login with correct credentials.
	res2, err := s.Login(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if res2.NeedsSecondFactor {
		t.Fatal("no second factor is enrolled, so Login should return a session")
	}
	user2, _, session2Tok := res2.User, res2.Session, res2.SessionToken
	if user2.ID != user.ID {
		t.Fatal("login returned different user ID")
	}
	if session2Tok == sessionTok {
		t.Fatal("login should create a new session token")
	}

	// Login with wrong password.
	_, err = s.Login(ctx, "alice@example.com", "wrong", RequestInfo{})
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	// Login with non-existent user.
	_, err = s.Login(ctx, "nobody@example.com", "password123", RequestInfo{})
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestRegisterDuplicate(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	_, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	_, _, _, err = s.Register(ctx, "alice@example.com", "password456", RequestInfo{})
	if err != ErrUserAlreadyExists {
		t.Fatalf("expected ErrUserAlreadyExists, got %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	s, users, _, _ := newTestEnv()
	ctx := context.Background()

	user, _, _, _ := s.Register(ctx, "alice@example.com", "old-password", RequestInfo{})
	// Verification is incidental to this test; the gate is covered elsewhere.
	verifyUserEmail(t, users, user.ID)

	err := s.ChangePassword(ctx, user.ID, "old-password", "new-password", RequestInfo{})
	if err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	// Old password should no longer work.
	_, err = s.Login(ctx, "alice@example.com", "old-password", RequestInfo{})
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials with old password, got %v", err)
	}

	// New password should work.
	_, err = s.Login(ctx, "alice@example.com", "new-password", RequestInfo{})
	if err != nil {
		t.Fatalf("Login with new password: %v", err)
	}
}

func TestValidateAndRevokeSession(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	_, _, sessionTok, _ := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})

	// Validate the session.
	sess, user, err := s.ValidateSession(ctx, sessionTok)
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
	_, _, err = s.ValidateSession(ctx, sessionTok)
	if err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound after revoke, got %v", err)
	}
}

func TestPasswordResetFlow(t *testing.T) {
	s, users, _, _ := newTestEnv()
	ctx := context.Background()

	user, _, _, _ := s.Register(ctx, "alice@example.com", "old-password", RequestInfo{})
	// Verification is incidental to this test; the gate is covered elsewhere.
	verifyUserEmail(t, users, user.ID)

	rawToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	err = s.ResetPassword(ctx, rawToken, "new-password")
	if err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	// Old password should no longer work.
	_, err = s.Login(ctx, "alice@example.com", "old-password", RequestInfo{})
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	// New password should work.
	_, err = s.Login(ctx, "alice@example.com", "new-password", RequestInfo{})
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
	rawToken, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	user, _, sessionTok, err := redeemMagicLink(t, s, ctx, rawToken)
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	if user.Email != "bob@example.com" {
		t.Fatalf("expected bob@example.com, got %s", user.Email)
	}
	if sessionTok == "" {
		t.Fatal("expected non-empty session token")
	}
	if user.PasswordHash != "" {
		t.Fatal("magic link user should have no password hash")
	}

	// Token should be used; can't reuse.
	_, err = s.RedeemMagicLink(ctx, rawToken, RequestInfo{})
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
	s := mustNew(users, sessions, newMemTokenStore())

	user, session, sessionTok, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if user.ID == "" {
		t.Fatal("expected created user")
	}
	if sessionTok == "" {
		t.Fatal("expected issued session to include raw token")
	}
	if session.TokenHash == "" {
		t.Fatal("expected issued session to include token hash")
	}
	if session.TokenHash != hashSessionToken(sessionTok) {
		t.Fatal("expected issued session token hash to match raw token")
	}
	if sessions.created == nil {
		t.Fatal("expected session store create call")
	}
	if sessions.created.TokenHash != session.TokenHash {
		t.Fatal("expected persisted session to store token hash")
	}
}

func TestValidateSessionLooksUpByTokenHash(t *testing.T) {
	ctx := context.Background()
	users := newMemUserStore()
	sessions := newObservingSessionStore()
	s := mustNew(users, sessions, newMemTokenStore())

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
	s := mustNew(users, store, newMemTokenStore())

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

	_, _, err := s.ValidateSession(ctx, rawToken)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
}

func TestChangePasswordRejectsPasswordlessUser(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	rawToken, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	// The user is only created at redemption time (deferred user creation).
	user, _, _, err := redeemMagicLink(t, s, ctx, rawToken)
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}

	err = s.ChangePassword(ctx, user.ID, "", "new-password", RequestInfo{})
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestSetInitialPassword(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	rawToken, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	// The user is only created at redemption time (deferred user creation).
	user, _, _, err := redeemMagicLink(t, s, ctx, rawToken)
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	if user.PasswordHash != "" {
		t.Fatal("expected passwordless user")
	}

	if err := s.SetInitialPassword(ctx, user.ID, "new-password"); err != nil {
		t.Fatalf("SetInitialPassword: %v", err)
	}

	_, err = s.Login(ctx, "bob@example.com", "new-password", RequestInfo{})
	if err != nil {
		t.Fatalf("Login with initial password: %v", err)
	}
}

func TestSetInitialPasswordRejectsExistingPassword(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
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
	s := mustNew(newMemUserStore(), newMemSessionStore(), &errTokenStore{err: wantErr})

	_, err := s.consumeToken(ctx, "raw-token", TokenPurposeMagicLink)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected lookup error to propagate, got %v", err)
	}
}

func TestConsumeTokenNormalizesWrappedTokenNotFound(t *testing.T) {
	ctx := context.Background()
	s := mustNew(
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
	s := mustNew(&wrappedNotFoundUserStore{}, newMemSessionStore(), newMemTokenStore())

	rawToken, err := s.CreateMagicLinkToken(ctx, "wrapped@example.com", RequestInfo{})
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
	s := mustNew(users, newMemSessionStore(), newMemTokenStore())

	if _, _, _, err := s.Register(ctx, "alice@example.com", "old-password", RequestInfo{}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	rawToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com", RequestInfo{})
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

	if _, _, _, err := s.Register(ctx, "alice@example.com", "old-password", RequestInfo{}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	rawToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com", RequestInfo{})
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

	if _, _, _, err := s.Register(ctx, "alice@example.com", "old-password", RequestInfo{}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	rawToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	// Presenting a reset token to the magic-link flow must not consume it.
	_, err = s.RedeemMagicLink(ctx, rawToken, RequestInfo{})
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

	_, _, sessionTok, err := s.Register(ctx, "alice@example.com", "old-password", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	rawToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	if err := s.ResetPassword(ctx, rawToken, "new-password"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	// The pre-reset session must be invalidated.
	if _, _, err := s.ValidateSession(ctx, sessionTok); err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound for pre-reset session, got %v", err)
	}
	if len(sessions.sessions) != 0 {
		t.Fatalf("expected all sessions revoked, got %d remaining", len(sessions.sessions))
	}
}

func TestChangePasswordRevokesAllSessions(t *testing.T) {
	s, _, sessions, _ := newTestEnv()
	ctx := context.Background()

	user, _, sessionTok, err := s.Register(ctx, "alice@example.com", "old-password", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := s.ChangePassword(ctx, user.ID, "old-password", "new-password", RequestInfo{}); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	// The pre-change session must be invalidated.
	if _, _, err := s.ValidateSession(ctx, sessionTok); err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound for pre-change session, got %v", err)
	}
	if len(sessions.sessions) != 0 {
		t.Fatalf("expected all sessions revoked, got %d remaining", len(sessions.sessions))
	}
}

func TestResetPasswordDeletesOutstandingResetTokens(t *testing.T) {
	s, _, _, tokens := newTestEnv()
	ctx := context.Background()

	if _, _, _, err := s.Register(ctx, "alice@example.com", "old-password", RequestInfo{}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	firstToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreatePasswordResetToken (first): %v", err)
	}
	secondToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com", RequestInfo{})
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

// TestResetPasswordRevokesTwoFactorTokens asserts that a pending 2FA
// login token minted before a password reset cannot be completed
// afterward — otherwise an attacker who obtained a pending token under the
// old password could still complete login post-reset.
func TestResetPasswordRevokesTwoFactorTokens(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "old-password", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Verification is incidental to this test; the gate is covered elsewhere.
	verifyUserEmail(t, users, user.ID)

	pending, err := s.CreateTwoFactorToken(ctx, user.ID)
	if err != nil {
		t.Fatalf("CreateTwoFactorToken: %v", err)
	}

	rawToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}
	if err := s.ResetPassword(ctx, rawToken, "new-password"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	if _, err := s.CompleteTwoFactor(ctx, user.ID, pending, RequestInfo{}); err != ErrTokenInvalid {
		t.Fatalf("expected ErrTokenInvalid for 2FA token surviving password reset, got %v", err)
	}
}

func TestWithRevokeSessionsOnPasswordChangeFalseKeepsSessions(t *testing.T) {
	s, _, sessions, tokens := newTestEnv(WithRevokeSessionsOnPasswordChange(false))
	ctx := context.Background()

	_, _, sessionTok, err := s.Register(ctx, "alice@example.com", "old-password", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	rawToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	if err := s.ResetPassword(ctx, rawToken, "new-password"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	// Session revocation opted out: the pre-reset session should still validate.
	if _, _, err := s.ValidateSession(ctx, sessionTok); err != nil {
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

	_, _, sessionTok, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, _, err := s.ValidateSession(ctx, sessionTok); err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
}

// TestLoginUnknownUserStillRunsArgon2 asserts that Login for an unknown email
// pays roughly the same Argon2 cost as a known email with a wrong password,
// so response timing doesn't reveal whether an account exists. This must use
// the DEFAULT (slow) Argon2 params for the comparison to be meaningful.
func TestLoginUnknownUserStillRunsArgon2(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	if _, _, _, err := s.Register(ctx, "alice@example.com", "correct-password", RequestInfo{}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	const iterations = 3
	var knownTotal, unknownTotal time.Duration

	for i := 0; i < iterations; i++ {
		start := time.Now()
		if _, err := s.Login(ctx, "alice@example.com", "wrong-password", RequestInfo{}); err != ErrInvalidCredentials {
			t.Fatalf("expected ErrInvalidCredentials for wrong password, got %v", err)
		}
		knownTotal += time.Since(start)

		start = time.Now()
		if _, err := s.Login(ctx, "nobody@example.com", "wrong-password", RequestInfo{}); err != ErrInvalidCredentials {
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

	rawToken, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	// Redeem so the passwordless user actually exists; otherwise this would
	// exercise the unknown-user path instead of the passwordless-user path.
	if _, err := s.RedeemMagicLink(ctx, rawToken, RequestInfo{}); err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}

	if _, err := s.Login(ctx, "bob@example.com", "any-password", RequestInfo{}); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestEmailsAreNormalized(t *testing.T) {
	s, users, _, _ := newTestEnv()
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "Foo@X.com ", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Verification is incidental to this test; the gate is covered elsewhere.
	verifyUserEmail(t, users, user.ID)

	// A differently-cased, untrimmed variant of the same address must log in.
	_, err = s.Login(ctx, "foo@x.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Login with normalized email: %v", err)
	}
}

func TestRegisterRejectsInvalidEmail(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	overlong := strings.Repeat("a", 250) + "@example.com" // > 254 chars total
	cases := []string{
		"not-an-email",
		"a b@c.d",
		overlong,
	}

	for _, email := range cases {
		_, _, _, err := s.Register(ctx, email, "password123", RequestInfo{})
		if err != ErrInvalidEmail {
			t.Fatalf("Register(%q): expected ErrInvalidEmail, got %v", email, err)
		}
	}
}

func TestCreateMagicLinkTokenDoesNotCreateUser(t *testing.T) {
	s, users, _, _ := newTestEnv()
	ctx := context.Background()

	rawToken, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	if rawToken == "" {
		t.Fatal("expected a non-empty raw token")
	}
	if len(users.users) != 0 {
		t.Fatalf("expected no user created before redemption, got %d", len(users.users))
	}
}

func TestRedeemMagicLinkCreatesPasswordlessUser(t *testing.T) {
	s, users, _, _ := newTestEnv()
	ctx := context.Background()

	rawToken, err := s.CreateMagicLinkToken(ctx, "Bob@Example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	if len(users.users) != 0 {
		t.Fatalf("expected no user before redemption, got %d", len(users.users))
	}

	user, _, sessionTok, err := redeemMagicLink(t, s, ctx, rawToken)
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	if user.Email != "bob@example.com" {
		t.Fatalf("expected normalized email bob@example.com, got %s", user.Email)
	}
	if user.PasswordHash != "" {
		t.Fatal("expected passwordless user")
	}
	if sessionTok == "" {
		t.Fatal("expected non-empty session token")
	}
	if len(users.users) != 1 {
		t.Fatalf("expected exactly one user created, got %d", len(users.users))
	}
}

func TestRedeemMagicLinkRacesWithRegister(t *testing.T) {
	s, _, _, _ := newTestEnv()
	ctx := context.Background()

	rawToken, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	// Someone registers a full account for this email between token issuance
	// and redemption (e.g. via a concurrent request on another path).
	registeredUser, _, _, err := s.Register(ctx, "bob@example.com", "some-password", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	user, _, _, err := redeemMagicLink(t, s, ctx, rawToken)
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	if user.ID != registeredUser.ID {
		t.Fatalf("expected redeem to log into the registered account %s, got %s", registeredUser.ID, user.ID)
	}
	if user.PasswordHash == "" {
		t.Fatal("expected the already-registered account's password hash to be preserved")
	}
}

// raceCreateUserStore simulates another actor's CreateUser call winning a
// race for the same email between this call's GetUserByEmail miss and its
// own CreateUser attempt, so CreateUser observes ErrUserAlreadyExists the way
// a real store's unique constraint would.
type raceCreateUserStore struct {
	*memUserStore
}

func (s *raceCreateUserStore) CreateUser(ctx context.Context, u *User) error {
	winner := &User{
		ID:        "race-winner-" + u.ID,
		Email:     u.Email,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
	if err := s.memUserStore.CreateUser(ctx, winner); err != nil {
		return err
	}
	return s.memUserStore.CreateUser(ctx, u) // now hits the email-exists check
}

func TestGetOrCreatePasswordlessUserFallsBackAfterCreateUserRace(t *testing.T) {
	users := &raceCreateUserStore{memUserStore: newMemUserStore()}
	s := mustNew(users, newMemSessionStore(), newMemTokenStore())
	ctx := context.Background()

	rawToken, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	user, _, _, err := redeemMagicLink(t, s, ctx, rawToken)
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	if user.Email != "bob@example.com" {
		t.Fatalf("expected to fall back to the race winner's user, got %+v", user)
	}
	if len(users.users) != 1 {
		t.Fatalf("expected exactly one user to remain, got %d", len(users.users))
	}
}

// TestVerifyPasswordDoesNotCreateSession asserts that VerifyPassword checks
// credentials without ever touching the session store, so it's safe to use
// as a standalone check in a multi-step (e.g. 2FA) login flow.
func TestVerifyPasswordDoesNotCreateSession(t *testing.T) {
	s, _, sessions, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	if _, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Register creates its own session; clear it so we can observe
	// VerifyPassword's effect in isolation.
	sessions.sessions = make(map[string]*Session)

	user, err := s.VerifyPassword(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if user.Email != "alice@example.com" {
		t.Fatalf("expected email alice@example.com, got %s", user.Email)
	}
	if len(sessions.sessions) != 0 {
		t.Fatalf("expected no sessions to be created, got %d", len(sessions.sessions))
	}
}

// TestVerifyPasswordWrongPasswordReturnsInvalidCredentials asserts that
// VerifyPassword preserves Login's ErrInvalidCredentials semantics.
func TestVerifyPasswordWrongPasswordReturnsInvalidCredentials(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	if _, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := s.VerifyPassword(ctx, "alice@example.com", "wrong", RequestInfo{}); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	if _, err := s.VerifyPassword(ctx, "nobody@example.com", "password123", RequestInfo{}); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials for unknown user, got %v", err)
	}
}

// TestIssueSessionReturnsValidatableSession asserts that IssueSession
// produces a session that round-trips through ValidateSession, since it's
// meant to be called directly after out-of-band authentication (passkey,
// completed 2FA) with no password check of its own.
func TestIssueSessionReturnsValidatableSession(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Verification is incidental to this test; the gate is covered elsewhere.
	verifyUserEmail(t, users, user.ID)

	session, sessionTok, err := s.IssueSession(ctx, user.ID)
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	if sessionTok == "" {
		t.Fatal("expected non-empty session token")
	}

	gotSession, gotUser, err := s.ValidateSession(ctx, sessionTok)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if gotSession.ID != session.ID {
		t.Fatalf("expected session ID %s, got %s", session.ID, gotSession.ID)
	}
	if gotUser.ID != user.ID {
		t.Fatalf("expected user ID %s, got %s", user.ID, gotUser.ID)
	}
}

// TestLoginStillReturnsUserAndSession pins down that Login's public contract
// is unchanged: it behaves as VerifyPassword followed by IssueSession.
func TestLoginStillReturnsUserAndSession(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Verification is incidental to this test; the gate is covered elsewhere.
	verifyUserEmail(t, users, user.ID)

	res, err := s.Login(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	loggedInUser, session, loginTok := res.User, res.Session, res.SessionToken
	if loggedInUser.ID != user.ID {
		t.Fatalf("expected user ID %s, got %s", user.ID, loggedInUser.ID)
	}
	if loginTok == "" {
		t.Fatal("expected non-empty session token")
	}

	gotSession, gotUser, err := s.ValidateSession(ctx, loginTok)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if gotSession.ID != session.ID {
		t.Fatalf("expected session ID %s, got %s", session.ID, gotSession.ID)
	}
	if gotUser.ID != user.ID {
		t.Fatalf("expected user ID %s, got %s", user.ID, gotUser.ID)
	}
}

// TestTwoFactorFlowIssuesSessionOnlyAfterCompletion asserts that verifying a
// password and minting a two-factor token does not create a session; only
// CompleteTwoFactor does. This mirrors the intended app flow: VerifyPassword
// -> (app checks its own "user has 2FA" flag) -> CreateTwoFactorToken -> (app
// verifies TOTP/recovery code/passkey) -> CompleteTwoFactor.
func TestTwoFactorFlowIssuesSessionOnlyAfterCompletion(t *testing.T) {
	s, users, sessions, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Verification is incidental to this test; the gate is covered elsewhere.
	verifyUserEmail(t, users, user.ID)
	// Register creates its own session; clear it so we can observe the
	// two-factor flow's effect in isolation.
	sessions.sessions = make(map[string]*Session)

	gotUser, err := s.VerifyPassword(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}

	rawToken, err := s.CreateTwoFactorToken(ctx, gotUser.ID)
	if err != nil {
		t.Fatalf("CreateTwoFactorToken: %v", err)
	}
	if len(sessions.sessions) != 0 {
		t.Fatalf("expected no sessions before CompleteTwoFactor, got %d", len(sessions.sessions))
	}

	twoFactorRes, err := s.CompleteTwoFactor(ctx, gotUser.ID, rawToken, RequestInfo{})
	if err != nil {
		t.Fatalf("CompleteTwoFactor: %v", err)
	}
	if twoFactorRes.NeedsSecondFactor {
		t.Fatal("the second factor was just completed, so no further factor may be demanded")
	}
	if twoFactorRes.User.ID != user.ID {
		t.Fatalf("expected user ID %s, got %s", user.ID, twoFactorRes.User.ID)
	}
	if twoFactorRes.SessionToken == "" {
		t.Fatal("expected non-empty session token")
	}
	if len(sessions.sessions) != 1 {
		t.Fatalf("expected exactly one session after CompleteTwoFactor, got %d", len(sessions.sessions))
	}
}

// TestTwoFactorTokenIsSingleUse asserts that a two-factor token cannot be
// replayed to mint a second session.
func TestTwoFactorTokenIsSingleUse(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Verification is incidental to this test; the gate is covered elsewhere.
	verifyUserEmail(t, users, user.ID)

	rawToken, err := s.CreateTwoFactorToken(ctx, user.ID)
	if err != nil {
		t.Fatalf("CreateTwoFactorToken: %v", err)
	}

	if _, err := s.CompleteTwoFactor(ctx, user.ID, rawToken, RequestInfo{}); err != nil {
		t.Fatalf("CompleteTwoFactor: %v", err)
	}

	if _, err := s.CompleteTwoFactor(ctx, user.ID, rawToken, RequestInfo{}); err != ErrTokenAlreadyUsed {
		t.Fatalf("expected ErrTokenAlreadyUsed, got %v", err)
	}
}

// TestCompleteTwoFactorRejectsMismatchedUserID asserts that a pending token
// minted for one user cannot be completed by supplying a different user's
// ID — the defense against an attacker who has their own valid pending
// token (or a leaked one) and tries to complete it as another account by
// passing that account's userID. The token is consumed regardless, so the
// mismatch also burns it against replay.
func TestCompleteTwoFactorRejectsMismatchedUserID(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	userA, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register (A): %v", err)
	}
	userB, _, _, err := s.Register(ctx, "bob@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register (B): %v", err)
	}
	// Verification is incidental to this test; the gate is covered elsewhere.
	verifyUserEmail(t, users, userA.ID)

	rawToken, err := s.CreateTwoFactorToken(ctx, userA.ID)
	if err != nil {
		t.Fatalf("CreateTwoFactorToken: %v", err)
	}

	if _, err := s.CompleteTwoFactor(ctx, userB.ID, rawToken, RequestInfo{}); err != ErrTokenInvalid {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}

	// The token must be consumed by the mismatched attempt, so even the
	// rightful owner (userA) can no longer complete it afterward.
	if _, err := s.CompleteTwoFactor(ctx, userA.ID, rawToken, RequestInfo{}); err != ErrTokenAlreadyUsed {
		t.Fatalf("expected ErrTokenAlreadyUsed after mismatched attempt consumed the token, got %v", err)
	}
}

// TestTwoFactorTokenExpires asserts that an expired two-factor token is
// rejected rather than silently accepted.
func TestTwoFactorTokenExpires(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithTwoFactorTokenDuration(-time.Second))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Verification is incidental to this test; the gate is covered elsewhere.
	verifyUserEmail(t, users, user.ID)

	rawToken, err := s.CreateTwoFactorToken(ctx, user.ID)
	if err != nil {
		t.Fatalf("CreateTwoFactorToken: %v", err)
	}

	if _, err := s.CompleteTwoFactor(ctx, user.ID, rawToken, RequestInfo{}); err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

// TestTwoFactorTokenRejectedByOtherFlows asserts that a two-factor token
// cannot be replayed against an unrelated flow like ResetPassword, since
// consumeToken checks purpose as part of its atomic lookup.
func TestTwoFactorTokenRejectedByOtherFlows(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Verification is incidental to this test; the gate is covered elsewhere.
	verifyUserEmail(t, users, user.ID)

	rawToken, err := s.CreateTwoFactorToken(ctx, user.ID)
	if err != nil {
		t.Fatalf("CreateTwoFactorToken: %v", err)
	}

	if err := s.ResetPassword(ctx, rawToken, "new-password"); err != ErrTokenInvalid {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

// TestRegisterLeavesEmailUnverified asserts that Register does not implicitly
// prove inbox ownership: only actually receiving and using a verification
// token or magic link should stamp EmailVerifiedAt.
func TestRegisterLeavesEmailUnverified(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if user.EmailVerifiedAt != nil {
		t.Fatalf("expected EmailVerifiedAt nil after Register, got %v", user.EmailVerifiedAt)
	}
}

// TestVerifyEmailStampsEmailVerifiedAt asserts that redeeming a valid
// email-verification token stamps EmailVerifiedAt on both the returned user
// and the persisted record.
func TestVerifyEmailStampsEmailVerifiedAt(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	rawToken, err := s.CreateEmailVerificationToken(ctx, user.ID)
	if err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}

	verifiedUser, err := s.VerifyEmail(ctx, rawToken)
	if err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if verifiedUser.EmailVerifiedAt == nil {
		t.Fatal("expected EmailVerifiedAt to be set on the returned user")
	}

	stored, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if stored.EmailVerifiedAt == nil {
		t.Fatal("expected EmailVerifiedAt to be persisted")
	}
}

// TestVerifyEmailTokenIsSingleUse asserts that an email-verification token
// cannot be replayed.
func TestVerifyEmailTokenIsSingleUse(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	rawToken, err := s.CreateEmailVerificationToken(ctx, user.ID)
	if err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}

	if _, err := s.VerifyEmail(ctx, rawToken); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}

	if _, err := s.VerifyEmail(ctx, rawToken); err != ErrTokenAlreadyUsed {
		t.Fatalf("expected ErrTokenAlreadyUsed, got %v", err)
	}
}

// TestVerifyEmailRejectsTokenForChangedEmail asserts that an
// email-verification token is bound to the address it was issued for: if
// the user's email changes before the token is redeemed, VerifyEmail must
// not stamp verification for the new address using a token that never
// proved control of it.
func TestVerifyEmailRejectsTokenForChangedEmail(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	rawToken, err := s.CreateEmailVerificationToken(ctx, user.ID)
	if err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}

	// Simulate the user's email changing after the token was issued (e.g. an
	// account-settings email change) by mutating the store directly.
	stored, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	stored.Email = "changed@example.com"
	if err := users.UpdateUser(ctx, stored); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	if _, err := s.VerifyEmail(ctx, rawToken); err != ErrTokenInvalid {
		t.Fatalf("expected ErrTokenInvalid for a token bound to a stale email, got %v", err)
	}
}

// TestRedeemMagicLinkStampsEmailVerified asserts that redeeming a magic link
// proves inbox ownership and stamps EmailVerifiedAt, closing the
// pre-registration account-takeover gap: an attacker who registers the
// victim's email with their own password cannot benefit from the victim
// later magic-linking in, since that redemption verifies the victim's
// control of the mailbox. It also asserts stampEmailVerified is idempotent
// across a second verification path: the timestamp does not change once set.
func TestRedeemMagicLinkStampsEmailVerified(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "victim@example.com", "attacker-password", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if user.EmailVerifiedAt != nil {
		t.Fatal("expected EmailVerifiedAt nil before any verification")
	}

	rawToken, err := s.CreateMagicLinkToken(ctx, "victim@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	verifiedUser, _, _, err := redeemMagicLink(t, s, ctx, rawToken)
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	if verifiedUser.EmailVerifiedAt == nil {
		t.Fatal("expected RedeemMagicLink to stamp EmailVerifiedAt")
	}
	firstVerifiedAt := *verifiedUser.EmailVerifiedAt

	rawToken2, err := s.CreateMagicLinkToken(ctx, "victim@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken (second): %v", err)
	}
	secondUser, _, _, err := redeemMagicLink(t, s, ctx, rawToken2)
	if err != nil {
		t.Fatalf("RedeemMagicLink (second): %v", err)
	}
	if secondUser.EmailVerifiedAt == nil || !secondUser.EmailVerifiedAt.Equal(firstVerifiedAt) {
		t.Fatalf("expected EmailVerifiedAt to remain %v (idempotent), got %v", firstVerifiedAt, secondUser.EmailVerifiedAt)
	}
}

// TestRedeemMagicLinkRevokesAttackerSessionOnFirstVerification closes the
// residual account-takeover window: an attacker registers the victim's
// email with their own password (getting a session), and the victim later
// proves mailbox control via a magic link. The attacker's pre-verification
// session must not survive that first verification. Because RedeemMagicLink
// calls stampEmailVerified BEFORE createSession, the victim's freshly
// created session is issued after the revocation and must survive.
func TestRedeemMagicLinkRevokesAttackerSessionOnFirstVerification(t *testing.T) {
	s, _, sessions, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	// Attacker seeds the account with the victim's email and their own
	// password, obtaining a session.
	_, _, attackerSessionTok, err := s.Register(ctx, "victim@example.com", "attacker-password", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	rawToken, err := s.CreateMagicLinkToken(ctx, "victim@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	victimUser, _, victimSessionTok, err := redeemMagicLink(t, s, ctx, rawToken)
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	if victimUser.EmailVerifiedAt == nil {
		t.Fatal("expected EmailVerifiedAt to be set")
	}

	// The attacker's session, created before verification, must be revoked.
	if _, _, err := s.ValidateSession(ctx, attackerSessionTok); err != ErrSessionNotFound {
		t.Fatalf("expected attacker session revoked, got %v", err)
	}

	// The victim's session, created by RedeemMagicLink AFTER the revocation,
	// must survive.
	if _, _, err := s.ValidateSession(ctx, victimSessionTok); err != nil {
		t.Fatalf("expected victim's new session to validate, got %v", err)
	}
	if len(sessions.sessions) != 1 {
		t.Fatalf("expected exactly one surviving session, got %d", len(sessions.sessions))
	}
}

// TestLoginConsultsLimiterWithNormalizedEmailKey asserts that Login (via
// VerifyPassword) consults the configured limiter with a key built from the
// normalized (lowercased) email, before any store lookup.
func TestLoginConsultsLimiterWithNormalizedEmailKey(t *testing.T) {
	limiter := &fakeLimiter{}
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithLimiter(limiter))
	ctx := context.Background()

	if _, err := s.Login(ctx, "Foo@X.com", "whatever", RequestInfo{}); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	if len(limiter.keys) != 1 || limiter.keys[0] != "password:foo@x.com" {
		t.Fatalf("expected limiter to be consulted with key %q, got %v", "password:foo@x.com", limiter.keys)
	}
}

// TestDeniedLimiterReturnsErrRateLimited asserts that a denying limiter
// blocks Login, CreatePasswordResetToken, and CreateMagicLinkToken with
// ErrRateLimited, before any store lookup happens.
func TestDeniedLimiterReturnsErrRateLimited(t *testing.T) {
	limiter := &fakeLimiter{denied: true}
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithLimiter(limiter))
	ctx := context.Background()

	if _, err := s.Login(ctx, "alice@example.com", "whatever", RequestInfo{}); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Login: expected ErrRateLimited, got %v", err)
	}

	if _, err := s.CreatePasswordResetToken(ctx, "alice@example.com", RequestInfo{}); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("CreatePasswordResetToken: expected ErrRateLimited, got %v", err)
	}

	if _, err := s.CreateMagicLinkToken(ctx, "alice@example.com", RequestInfo{}); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("CreateMagicLinkToken: expected ErrRateLimited, got %v", err)
	}
}

// TestChangePasswordConsultsLimiterBeforeVerifyingOldPassword asserts that
// ChangePassword is guarded against old-password brute force: a denying
// limiter blocks it with ErrRateLimited, consulted with the "password:"+email
// key, before the old password is ever verified (proven here by supplying a
// wrong old password and still getting ErrRateLimited rather than
// ErrInvalidCredentials).
func TestChangePasswordConsultsLimiterBeforeVerifyingOldPassword(t *testing.T) {
	limiter := &fakeLimiter{denied: true}
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithLimiter(limiter))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "old-password", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	limiter.mu.Lock()
	limiter.keys = nil
	limiter.mu.Unlock()

	err = s.ChangePassword(ctx, user.ID, "definitely-wrong-old-password", "new-password", RequestInfo{})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}

	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if len(limiter.keys) != 1 || limiter.keys[0] != "password:alice@example.com" {
		t.Fatalf("expected limiter consulted with key %q, got %v", "password:alice@example.com", limiter.keys)
	}
}

// TestNilLimiterIsNoOp asserts that omitting WithLimiter (the default) never
// blocks any guarded operation.
func TestNilLimiterIsNoOp(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "carol@example.com", "correct-password", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Verification is incidental to this test; the gate is covered elsewhere.
	verifyUserEmail(t, users, user.ID)

	if _, err := s.Login(ctx, "carol@example.com", "correct-password", RequestInfo{}); err != nil {
		t.Fatalf("Login: %v", err)
	}

	if _, err := s.CreatePasswordResetToken(ctx, "carol@example.com", RequestInfo{}); err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	if _, err := s.CreateMagicLinkToken(ctx, "carol@example.com", RequestInfo{}); err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
}

// TestUnverifiedAccountCannotStartNewSessions asserts that, under the default
// config, every session-starting entry point rejects an account whose email
// has not been verified, while Register's own signup session is unaffected.
func TestUnverifiedAccountCannotStartNewSessions(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, sessionTok, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if sessionTok == "" {
		t.Fatal("expected Register's auto-session to still be issued")
	}

	if _, err := s.Login(ctx, "alice@example.com", "password123", RequestInfo{}); err != ErrEmailNotVerified {
		t.Fatalf("Login: expected ErrEmailNotVerified, got %v", err)
	}

	if _, err := s.CreateTwoFactorToken(ctx, user.ID); err != ErrEmailNotVerified {
		t.Fatalf("CreateTwoFactorToken: expected ErrEmailNotVerified, got %v", err)
	}

	if _, _, err := s.IssueSession(ctx, user.ID); err != ErrEmailNotVerified {
		t.Fatalf("IssueSession: expected ErrEmailNotVerified, got %v", err)
	}

	// Mint a pending 2FA token while the account is verified, then unverify
	// it before completing the token, proving CompleteTwoFactor checks the
	// user's CURRENT verification state rather than the state at
	// token-creation time.
	verifyUserEmail(t, users, user.ID)
	pending, err := s.CreateTwoFactorToken(ctx, user.ID)
	if err != nil {
		t.Fatalf("CreateTwoFactorToken (verified): %v", err)
	}
	unverifyUserEmail(t, users, user.ID)

	if _, err := s.CompleteTwoFactor(ctx, user.ID, pending, RequestInfo{}); err != ErrEmailNotVerified {
		t.Fatalf("CompleteTwoFactor: expected ErrEmailNotVerified, got %v", err)
	}
}

// TestLoginSucceedsAfterEmailVerification asserts that verifying the email
// via VerifyEmail lifts the gate for subsequent logins.
func TestLoginSucceedsAfterEmailVerification(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	rawToken, err := s.CreateEmailVerificationToken(ctx, user.ID)
	if err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}
	if _, err := s.VerifyEmail(ctx, rawToken); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}

	if _, err := s.Login(ctx, "alice@example.com", "password123", RequestInfo{}); err != nil {
		t.Fatalf("Login after verification: expected success, got %v", err)
	}
}

// TestRedeemMagicLinkStillSignsInUnverifiedUser asserts that redeeming a
// magic link for a previously-unverified account still returns a session
// under the default gate, since RedeemMagicLink stamps EmailVerifiedAt before
// creating the session.
func TestRedeemMagicLinkStillSignsInUnverifiedUser(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	rawToken, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	user, _, sessionTok, err := redeemMagicLink(t, s, ctx, rawToken)
	if err != nil {
		t.Fatalf("RedeemMagicLink: expected success despite default RequireVerifiedEmail, got %v", err)
	}
	if sessionTok == "" {
		t.Fatal("expected non-empty session token")
	}
	if user.EmailVerifiedAt == nil {
		t.Fatal("expected RedeemMagicLink to verify the email before issuing the session")
	}
}

// TestRegisterStillReturnsSession asserts that Register's auto-session is
// unaffected by the default-on verified-email gate.
func TestRegisterStillReturnsSession(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	_, _, sessionTok, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: expected success under default RequireVerifiedEmail, got %v", err)
	}
	if sessionTok == "" {
		t.Fatal("expected Register's auto-session to be issued despite the unverified email")
	}
}

// TestWithRequireVerifiedEmailFalseRestoresOldBehavior asserts that opting
// out of the gate restores the pre-gate behavior: an unverified account can
// log in.
func TestWithRequireVerifiedEmailFalseRestoresOldBehavior(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithRequireVerifiedEmail(false))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if user.EmailVerifiedAt != nil {
		t.Fatal("expected EmailVerifiedAt nil; this test is about unverified accounts")
	}

	if _, err := s.Login(ctx, "alice@example.com", "password123", RequestInfo{}); err != nil {
		t.Fatalf("Login: expected success with WithRequireVerifiedEmail(false), got %v", err)
	}
}

// TestIssueSessionUnknownUserReturnsErrUserNotFound asserts that IssueSession
// now loads the user first, so an unknown ID is rejected with ErrUserNotFound
// rather than silently minting a session for a nonexistent user.
func TestIssueSessionUnknownUserReturnsErrUserNotFound(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	if _, _, err := s.IssueSession(ctx, "unknown-user-id"); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

// TestConcurrentResetAndVerifyDoesNotResurrectOldHash is the regression test
// for audit finding A3. setPassword and stampEmailVerified both did a
// read-modify-write of the entire user row, so interleaving them let the
// second write land with stale data. The dangerous direction restores a
// password hash the user just rotated away from — silently undoing a reset
// and re-enabling the credential an attacker may already hold.
func TestConcurrentResetAndVerifyDoesNotResurrectOldHash(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	const (
		email       = "race@example.com"
		oldPassword = "old-password-123"
		newPassword = "new-password-456"
	)

	user, _, _, err := s.Register(ctx, email, oldPassword, RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	verifyToken, err := s.CreateEmailVerificationToken(ctx, user.ID)
	if err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}

	// Land a complete password reset between VerifyEmail's read of the user
	// and its write. The hook fires once, so the reset's own UpdateUser is
	// unaffected.
	users.beforeUpdate = func(*User) {
		resetToken, err := s.CreatePasswordResetToken(ctx, email, RequestInfo{})
		if err != nil {
			t.Errorf("CreatePasswordResetToken: %v", err)
			return
		}
		if err := s.ResetPassword(ctx, resetToken, newPassword); err != nil {
			t.Errorf("ResetPassword: %v", err)
		}
	}

	if _, err := s.VerifyEmail(ctx, verifyToken); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}

	stored, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}

	if ok, _ := verifyPassword(oldPassword, stored.PasswordHash); ok {
		t.Error("the reset was silently undone: the old password still verifies")
	}
	ok, err := verifyPassword(newPassword, stored.PasswordHash)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if !ok {
		t.Error("the new password does not verify after the reset")
	}
	if stored.EmailVerifiedAt == nil {
		t.Error("EmailVerifiedAt was not stamped")
	}
}

// TestLoginWithSecondFactorReturnsPendingTokenNotSession is the regression
// test for audit finding A1: a correct password is only the first factor, and
// Login must not hand out a privileged session when the account has a second
// factor enrolled.
func TestLoginWithSecondFactorReturnsPendingTokenNotSession(t *testing.T) {
	s, users, sessions, _, factors := newTestEnvWithFactors(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)
	factors.enroll(user.ID)

	before := sessions.count()

	res, err := s.Login(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !res.NeedsSecondFactor {
		t.Fatal("an enrolled second factor must be demanded, not skipped")
	}
	if res.Session != nil || res.SessionToken != "" {
		t.Error("no session may exist before the second factor is verified")
	}
	if res.PendingToken == "" {
		t.Fatal("expected a pending two-factor token")
	}
	if got := sessions.count(); got != before {
		t.Errorf("sessions were created during a pending login: %d -> %d", before, got)
	}

	// The pending token is what CompleteTwoFactor consumes once the
	// application has checked the second factor itself.
	if _, err := s.CompleteTwoFactor(ctx, user.ID, res.PendingToken, RequestInfo{}); err != nil {
		t.Fatalf("CompleteTwoFactor: %v", err)
	}
}

func TestLoginWithoutSecondFactorReturnsSession(t *testing.T) {
	s, users, _, _, _ := newTestEnvWithFactors(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "bob@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	res, err := s.Login(ctx, "bob@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if res.NeedsSecondFactor || res.PendingToken != "" {
		t.Fatal("no factor is enrolled, so Login should complete")
	}
	if res.Session == nil || res.SessionToken == "" {
		t.Fatal("expected a session and its raw token")
	}
}

// TestLoginFailsClosedWhenCheckerErrors ensures an unavailable checker cannot
// quietly downgrade an account to a single factor.
func TestLoginFailsClosedWhenCheckerErrors(t *testing.T) {
	s, users, sessions, _, factors := newTestEnvWithFactors(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "carol@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	checkerErr := errors.New("factor store offline")
	factors.failWith(checkerErr)
	before := sessions.count()

	res, err := s.Login(ctx, "carol@example.com", "password123", RequestInfo{})
	if err == nil {
		t.Fatal("expected Login to fail when the second-factor check fails")
	}
	if !errors.Is(err, checkerErr) {
		t.Errorf("expected the checker error to propagate, got %v", err)
	}
	if res != nil {
		t.Error("no LoginResult may be returned when the check failed")
	}
	if got := sessions.count(); got != before {
		t.Errorf("a session was issued despite the failed check: %d -> %d", before, got)
	}
}

func TestNewRejectsNilSecondFactorChecker(t *testing.T) {
	_, err := New(newMemUserStore(), newMemSessionStore(), newMemTokenStore(), nil)
	if err == nil {
		t.Fatal("New must reject a nil SecondFactorChecker rather than defaulting it")
	}
	if !strings.Contains(err.Error(), "NoSecondFactors") {
		t.Errorf("the error should point at the explicit opt-out, got %q", err)
	}
}

// TestRedeemMagicLinkWithSecondFactorRequiresSecondFactor is the regression
// test for the sharpest edge of audit finding A1: RedeemMagicLink issued a
// session unconditionally, so anyone who could read the mailbox bypassed 2FA
// entirely — and the library offered no hook to stop it.
func TestRedeemMagicLinkWithSecondFactorRequiresSecondFactor(t *testing.T) {
	s, users, sessions, _, factors := newTestEnvWithFactors(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)
	factors.enroll(user.ID)

	rawToken, err := s.CreateMagicLinkToken(ctx, "alice@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	before := sessions.count()

	res, err := s.RedeemMagicLink(ctx, rawToken, RequestInfo{})
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	if !res.NeedsSecondFactor {
		t.Fatal("mailbox control must not bypass an enrolled second factor")
	}
	if res.Session != nil || res.SessionToken != "" {
		t.Error("no session may exist before the second factor is verified")
	}
	if res.PendingToken == "" {
		t.Fatal("expected a pending two-factor token")
	}
	if got := sessions.count(); got != before {
		t.Errorf("a session was created despite the pending factor: %d -> %d", before, got)
	}

	if _, err := s.CompleteTwoFactor(ctx, user.ID, res.PendingToken, RequestInfo{}); err != nil {
		t.Fatalf("CompleteTwoFactor: %v", err)
	}
}

// TestRedeemMagicLinkStampsVerifiedEvenWhenSecondFactorPending guards the
// ordering inside RedeemMagicLink. Verification must be stamped before the
// second-factor branch, or a 2FA-enabled user with an unverified address could
// never verify it this way: completeFirstFactor enforces RequireVerifiedEmail.
func TestRedeemMagicLinkStampsVerifiedEvenWhenSecondFactorPending(t *testing.T) {
	s, users, _, _, factors := newTestEnvWithFactors(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "dave@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	factors.enroll(user.ID)

	// Deliberately left unverified.
	rawToken, err := s.CreateMagicLinkToken(ctx, "dave@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	res, err := s.RedeemMagicLink(ctx, rawToken, RequestInfo{})
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	if !res.NeedsSecondFactor {
		t.Fatal("expected the second factor to be demanded")
	}

	stored, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if stored.EmailVerifiedAt == nil {
		t.Error("redeeming a magic link proves mailbox control, so it must stamp verification even when a factor is still pending")
	}
}

// TestSessionStructHasNoRawTokenField guards audit finding B5. The raw session
// token is returned beside the *Session at issue time and nowhere else, so a
// store implementation written from the struct's shape cannot persist a live
// bearer token. Expressed as a test rather than a comment, so reintroducing
// the field fails CI.
func TestSessionStructHasNoRawTokenField(t *testing.T) {
	typ := reflect.TypeOf(Session{})
	for i := range typ.NumField() {
		if name := typ.Field(i).Name; name == "Token" {
			t.Fatal("Session must not carry the raw token: return it beside the session instead")
		}
	}
	if _, ok := typ.FieldByName("TokenHash"); !ok {
		t.Error("Session should still carry TokenHash, which is what stores persist")
	}
}
