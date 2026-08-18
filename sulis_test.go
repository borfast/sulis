package sulis

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// In-memory store implementations for testing.
//
// These mirror the reference implementations in the memstore package, which
// are the ones adopters should read and which the storetest conformance suite
// is run against. They are duplicated rather than imported because these tests
// are in package sulis: memstore imports sulis, so importing memstore from
// here is an import cycle Go rejects outright ("import cycle not allowed in
// test"). Keep any behavioral change in step with memstore — a divergence here
// means these tests are passing against a store weaker than any real
// implementation is allowed to be.

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
	s.users[u.ID] = cloneTestUser(u)
	return nil
}

func (s *memUserStore) GetUserByID(_ context.Context, id string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return nil, ErrUserNotFound
	}
	return cloneTestUser(u), nil
}

func (s *memUserStore) GetUserByEmail(_ context.Context, email string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.Email == email {
			return cloneTestUser(u), nil
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
	// Email uniqueness, as UserStore.UpdateUser requires: a real store
	// enforces this with a UNIQUE index, so this test double must too, or
	// tests exercising the contract (e.g. two accounts racing to confirm a
	// change to the same address) would pass against a store weaker than
	// any real implementation is allowed to be.
	for id, other := range s.users {
		if id != u.ID && other.Email == u.Email {
			return ErrUserAlreadyExists
		}
	}
	cp := cloneTestUser(u)
	cp.Version = existing.Version + 1
	s.users[u.ID] = cp
	return nil
}

// cloneTestUser mirrors memstore's cloneUser: UserStore's contract forbids a
// store from sharing mutable state with its callers, and a plain struct copy
// shares Metadata's map and EmailVerifiedAt/DisabledAt/LockedUntil's
// pointers. Kept here so this double is not weaker than the contract
// storetest holds real stores to.
func cloneTestUser(u *User) *User {
	cp := *u
	if u.Metadata != nil {
		cp.Metadata = maps.Clone(u.Metadata)
	}
	if u.EmailVerifiedAt != nil {
		when := *u.EmailVerifiedAt
		cp.EmailVerifiedAt = &when
	}
	if u.DisabledAt != nil {
		when := *u.DisabledAt
		cp.DisabledAt = &when
	}
	if u.LockedUntil != nil {
		when := *u.LockedUntil
		cp.LockedUntil = &when
	}
	return &cp
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
	s.sessions[sess.ID] = cloneTestSession(sess)
	return nil
}

// cloneTestSession mirrors memstore's cloneSession; see cloneTestUser.
func cloneTestSession(sess *Session) *Session {
	cp := *sess
	if sess.Metadata != nil {
		cp.Metadata = maps.Clone(sess.Metadata)
	}
	return &cp
}

func (s *memSessionStore) GetSessionByTokenHash(_ context.Context, tokenHash string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessions {
		if sess.TokenHash == tokenHash {
			return cloneTestSession(sess), nil
		}
	}
	return nil, ErrSessionNotFound
}

func (s *memSessionStore) DeleteSession(_ context.Context, userID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok || sess.UserID != userID {
		return ErrSessionNotFound
	}
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

func (s *memSessionStore) UpdateAuthenticatedAt(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return ErrSessionNotFound
	}
	sess.AuthenticatedAt = at
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
	if err := s.RevokeSession(ctx, sess.UserID, sess.ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}

	// Session should no longer be valid.
	_, _, err = s.ValidateSession(ctx, sessionTok)
	if err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound after revoke, got %v", err)
	}
}

// TestRevokeSessionRejectsCrossUserAttempt guards against a session-management
// UI wired straight to RevokeSession letting user A revoke user B's session
// by guessing or leaking B's session ID: RevokeSession must scope the delete
// to the caller's own userID, so a mismatched owner leaves B's session
// completely untouched rather than deleting it.
func TestRevokeSessionRejectsCrossUserAttempt(t *testing.T) {
	s, _, sessions, _ := newTestEnv()
	ctx := context.Background()

	_, sessA, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register alice: %v", err)
	}
	_, sessB, tokB, err := s.Register(ctx, "bob@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register bob: %v", err)
	}

	// Alice tries to revoke Bob's session by guessing/leaking its ID.
	if err := s.RevokeSession(ctx, sessA.UserID, sessB.ID); err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound for cross-user revoke, got %v", err)
	}

	// Bob's session must still be intact and validatable.
	sess, user, err := s.ValidateSession(ctx, tokB)
	if err != nil {
		t.Fatalf("expected bob's session to remain valid, got %v", err)
	}
	if sess.ID != sessB.ID || user.ID != sessB.UserID {
		t.Fatalf("expected bob's original session/user, got session %s user %s", sess.ID, user.ID)
	}
	if got := sessions.count(); got != 2 {
		t.Fatalf("expected both sessions to remain stored, got %d", got)
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

// TestCreatePasswordResetTokenUnknownEmailReturnsEmptyResult asserts that an
// unregistered address gets ("", nil), not ErrUserNotFound — the endpoint
// must not let a caller distinguish a registered address from an
// unregistered one by its return value.
func TestCreatePasswordResetTokenUnknownEmailReturnsEmptyResult(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	token, err := s.CreatePasswordResetToken(ctx, "nobody@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("expected nil error for an unknown address, got %v", err)
	}
	if token != "" {
		t.Fatalf("expected an empty token for an unknown address, got %q", token)
	}
}

// TestCreatePasswordResetTokenUnknownEmailPerformsEquivalentWork asserts that
// the unknown-user path burns the same token-generation work the known-user
// path spends, then discards it rather than persisting it: a wrapped
// resetTokenGenerator proves the generation call actually happened, and the
// token store's row count proves nothing was written. An implementation that
// short-circuits before generating (returning ("", nil) immediately) already
// satisfies the return-value test above but must fail this one.
func TestCreatePasswordResetTokenUnknownEmailPerformsEquivalentWork(t *testing.T) {
	s, _, _, tokens := newTestEnv()
	ctx := context.Background()

	var calls int
	orig := resetTokenGenerator
	resetTokenGenerator = func(nBytes int) (string, string, error) {
		calls++
		return orig(nBytes)
	}
	defer func() { resetTokenGenerator = orig }()

	if _, err := s.CreatePasswordResetToken(ctx, "nobody@example.com", RequestInfo{}); err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	if calls != 1 {
		t.Fatalf("expected the unknown-user path to generate a token exactly once, got %d calls", calls)
	}
	if len(tokens.tokens) != 0 {
		t.Fatalf("expected the generated token to be discarded rather than persisted; store has %d rows", len(tokens.tokens))
	}
}

// TestCreatePasswordResetTokenStrictReturnsErrUserNotFound asserts that the
// Strict variant, meant for admin tooling that has already authenticated an
// operator, still returns ErrUserNotFound verbatim for an unknown address —
// unlike the public CreatePasswordResetToken, which must not leak that.
func TestCreatePasswordResetTokenStrictReturnsErrUserNotFound(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	if _, err := s.CreatePasswordResetTokenStrict(ctx, "nobody@example.com", RequestInfo{}); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

// TestCreatePasswordResetTokenStrictKnownEmailReturnsToken asserts that the
// Strict variant's known-user path is unaffected by the strict flag: it
// still generates and returns a usable reset token.
func TestCreatePasswordResetTokenStrictKnownEmailReturnsToken(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	if _, _, _, err := s.Register(ctx, "alice@example.com", "old-password", RequestInfo{}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	rawToken, err := s.CreatePasswordResetTokenStrict(ctx, "alice@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreatePasswordResetTokenStrict: %v", err)
	}
	if rawToken == "" {
		t.Fatal("expected a non-empty reset token for a known address")
	}

	if err := s.ResetPassword(ctx, rawToken, "new-password"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
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

func (s *observingSessionStore) DeleteSession(_ context.Context, userID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, sess := range s.sessionByHash {
		if sess.ID == id {
			if sess.UserID != userID {
				return ErrSessionNotFound
			}
			delete(s.sessionByHash, hash)
			return nil
		}
	}
	return ErrSessionNotFound
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

func (s *observingSessionStore) UpdateAuthenticatedAt(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessionByHash {
		if sess.ID == id {
			sess.AuthenticatedAt = at
			return nil
		}
	}
	return ErrSessionNotFound
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

func (s *sharedSessionStore) DeleteSession(_ context.Context, _, _ string) error { return nil }

func (s *sharedSessionStore) DeleteUserSessions(_ context.Context, _ string) error { return nil }

func (s *sharedSessionStore) CleanExpired(_ context.Context) error { return nil }

func (s *sharedSessionStore) UpdateAuthenticatedAt(_ context.Context, id string, at time.Time) error {
	if s.session == nil || s.session.ID != id {
		return ErrSessionNotFound
	}
	s.session.AuthenticatedAt = at
	return nil
}

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

// TestIssueSessionRejectsZeroValueAuthentication is the regression test for
// finding B6: IssueSession used to accept a bare userID, so any caller could
// mint a fully-privileged session for an arbitrary user with nothing proving
// they had actually authenticated. Authentication's zero value carries no
// user ID, and IssueSession must reject it with ErrNotAuthenticated rather
// than treating the empty string as a real (if unlikely) user ID.
func TestIssueSessionRejectsZeroValueAuthentication(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	if _, _, err := s.IssueSession(ctx, Authentication{}); err != ErrNotAuthenticated {
		t.Fatalf("expected ErrNotAuthenticated, got %v", err)
	}
}

// TestIssueSessionReturnsValidatableSession asserts that IssueSession
// produces a session that round-trips through ValidateSession, given a valid
// Authentication proof (minted here via newAuthentication, since only this
// package can construct one).
func TestIssueSessionReturnsValidatableSession(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Verification is incidental to this test; the gate is covered elsewhere.
	verifyUserEmail(t, users, user.ID)

	auth := newAuthentication(user.ID, AuthMethodPassword)
	session, sessionTok, err := s.IssueSession(ctx, auth)
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

// TestIssueSessionUncheckedCreatesValidatableSession asserts that
// IssueSessionUnchecked preserves IssueSession's old bare-userID behavior —
// under a name that says so in code review — for a factor sulis does not
// know about (e.g. a finished passkey ceremony).
func TestIssueSessionUncheckedCreatesValidatableSession(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	session, sessionTok, err := s.IssueSessionUnchecked(ctx, user.ID, AuthMethodPasskey)
	if err != nil {
		t.Fatalf("IssueSessionUnchecked: %v", err)
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

	if _, _, err := s.IssueSession(ctx, newAuthentication(user.ID, AuthMethodPassword)); err != ErrEmailNotVerified {
		t.Fatalf("IssueSession: expected ErrEmailNotVerified, got %v", err)
	}

	if _, _, err := s.IssueSessionUnchecked(ctx, user.ID, AuthMethodPasskey); err != ErrEmailNotVerified {
		t.Fatalf("IssueSessionUnchecked: expected ErrEmailNotVerified, got %v", err)
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

	if _, _, err := s.IssueSession(ctx, newAuthentication("unknown-user-id", AuthMethodPassword)); err != ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}

	if _, _, err := s.IssueSessionUnchecked(ctx, "unknown-user-id", AuthMethodPasskey); err != ErrUserNotFound {
		t.Fatalf("IssueSessionUnchecked: expected ErrUserNotFound, got %v", err)
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

// failSessionStore wraps a real memSessionStore but forces DeleteUserSessions
// to fail, so tests can cover the session-revocation error path.
type failSessionStore struct {
	*memSessionStore
	deleteUserSessionsErr error
}

func (s *failSessionStore) DeleteUserSessions(ctx context.Context, userID string) error {
	if s.deleteUserSessionsErr != nil {
		return s.deleteUserSessionsErr
	}
	return s.memSessionStore.DeleteUserSessions(ctx, userID)
}

// failGetUserStore wraps a real memUserStore but forces GetUserByID to fail,
// so tests can cover the user-lookup error paths in flows that load the user
// by ID.
type failGetUserStore struct {
	*memUserStore
	getErr error
}

func (s *failGetUserStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.memUserStore.GetUserByID(ctx, id)
}

// TestVerifyEmailIsANoOpWhenAnotherRequestVerifiesFirst covers
// stampEmailVerified's concurrent-verification guard. Two verification tokens
// for the same address are both valid, and a user who clicks an older link
// after a newer one has already landed must not be treated as an error — nor
// have the original verification timestamp overwritten, which is the whole
// reason the stamp is written under a guard rather than unconditionally.
//
// The interleaving is deterministic rather than timing-dependent: the
// beforeUpdate hook lands a complete second verification between this one's
// read and its write, so the optimistic-concurrency retry re-reads a row that
// is already verified and the guard fires on the second attempt.
func TestVerifyEmailIsANoOpWhenAnotherRequestVerifiesFirst(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	firstToken, err := s.CreateEmailVerificationToken(ctx, user.ID)
	if err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}
	secondToken, err := s.CreateEmailVerificationToken(ctx, user.ID)
	if err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}

	users.beforeUpdate = func(*User) {
		if _, err := s.VerifyEmail(ctx, secondToken); err != nil {
			t.Errorf("racing VerifyEmail: %v", err)
		}
	}

	beforeSecondVerification, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}

	if _, err := s.VerifyEmail(ctx, firstToken); err != nil {
		t.Fatalf("VerifyEmail: %v, want nil — losing the race to another verification of the same address is not a failure", err)
	}

	stored, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if stored.EmailVerifiedAt == nil {
		t.Fatal("EmailVerifiedAt is nil, want the timestamp written by the racing verification")
	}
	if beforeSecondVerification.EmailVerifiedAt != nil {
		t.Fatal("the user was already verified before the race was set up; the test proves nothing")
	}
}

// TestVerifyEmailPropagatesUserUpdateFailure covers stampEmailVerified's
// error path. A verification whose write never landed must be reported as a
// failure: returning nil would tell the caller the address is verified while
// the stored row still says it is not, and the token has already been burned.
func TestVerifyEmailPropagatesUserUpdateFailure(t *testing.T) {
	ctx := context.Background()
	updateErr := errors.New("update user failed")

	mem := newMemUserStore()
	users := &failUpdateUserStore{memUserStore: mem}
	sessions := newMemSessionStore()
	tokens := newMemTokenStore()
	s := mustNew(users, sessions, tokens, WithArgon2Params(testArgon2Params))

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	rawToken, err := s.CreateEmailVerificationToken(ctx, user.ID)
	if err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}

	users.updateErr = updateErr
	if _, err := s.VerifyEmail(ctx, rawToken); !errors.Is(err, updateErr) {
		t.Fatalf("VerifyEmail error = %v, want errors.Is(err, updateErr)", err)
	}
}

// TestVerifyEmailPropagatesSessionRevocationFailure covers the last step of
// stampEmailVerified: when an account that already has a password is verified
// for the first time, every existing session is revoked, because an attacker
// may have registered the victim's address with their own password before the
// victim ever proved mailbox control. If that revocation cannot be performed,
// the caller must hear about it rather than continue believing the attacker's
// sessions are gone.
func TestVerifyEmailPropagatesSessionRevocationFailure(t *testing.T) {
	ctx := context.Background()
	revokeErr := errors.New("delete user sessions failed")

	users := newMemUserStore()
	sessions := &failSessionStore{memSessionStore: newMemSessionStore()}
	s := mustNew(users, sessions, newMemTokenStore(), WithArgon2Params(testArgon2Params))

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	rawToken, err := s.CreateEmailVerificationToken(ctx, user.ID)
	if err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}

	sessions.deleteUserSessionsErr = revokeErr
	if _, err := s.VerifyEmail(ctx, rawToken); !errors.Is(err, revokeErr) {
		t.Fatalf("VerifyEmail error = %v, want errors.Is(err, revokeErr)", err)
	}
}

// TestEmailVerificationPropagatesUserLookupFailures covers the two
// GetUserByID calls in the email-verification flow. The VerifyEmail case
// matters most: its lookup happens after the token has been consumed, so a
// swallowed error there would burn the user's only token and report success
// without verifying anything.
func TestEmailVerificationPropagatesUserLookupFailures(t *testing.T) {
	ctx := context.Background()
	lookupErr := errors.New("user lookup failed")

	users := &failGetUserStore{memUserStore: newMemUserStore()}
	s := mustNew(users, newMemSessionStore(), newMemTokenStore(), WithArgon2Params(testArgon2Params))

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	rawToken, err := s.CreateEmailVerificationToken(ctx, user.ID)
	if err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}

	users.getErr = lookupErr

	if _, err := s.CreateEmailVerificationToken(ctx, user.ID); !errors.Is(err, lookupErr) {
		t.Fatalf("CreateEmailVerificationToken error = %v, want errors.Is(err, lookupErr)", err)
	}
	if _, err := s.VerifyEmail(ctx, rawToken); !errors.Is(err, lookupErr) {
		t.Fatalf("VerifyEmail error = %v, want errors.Is(err, lookupErr)", err)
	}
}

// --- T501: step-up authentication ---

// TestRequireRecentAuthOldStampReturnsErrReauthRequired asserts that a
// session whose AuthenticatedAt is older than maxAge is rejected.
func TestRequireRecentAuthOldStampReturnsErrReauthRequired(t *testing.T) {
	s := newTestSulis()
	session := &Session{AuthenticatedAt: time.Now().Add(-2 * time.Hour)}

	if err := s.RequireRecentAuth(context.Background(), session, time.Hour); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("RequireRecentAuth error = %v, want ErrReauthRequired", err)
	}
}

// TestRequireRecentAuthFreshStampReturnsNil asserts that a session
// authenticated within maxAge passes.
func TestRequireRecentAuthFreshStampReturnsNil(t *testing.T) {
	s := newTestSulis()
	session := &Session{AuthenticatedAt: time.Now().Add(-time.Minute)}

	if err := s.RequireRecentAuth(context.Background(), session, time.Hour); err != nil {
		t.Fatalf("RequireRecentAuth: %v", err)
	}
}

// TestRequireRecentAuthZeroAuthenticatedAtFailsClosed asserts that a session
// predating this feature (zero AuthenticatedAt) is always treated as stale,
// never as fresh.
func TestRequireRecentAuthZeroAuthenticatedAtFailsClosed(t *testing.T) {
	s := newTestSulis()
	session := &Session{} // AuthenticatedAt zero value

	if err := s.RequireRecentAuth(context.Background(), session, 24*time.Hour); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("RequireRecentAuth error = %v, want ErrReauthRequired", err)
	}
}

// TestReAuthenticateCorrectPasswordRefreshesAuthenticatedAt asserts that a
// correct password stamps the session's AuthenticatedAt without minting a
// new session or rotating its token: the same session ID and token hash
// still validate afterward.
func TestReAuthenticateCorrectPasswordRefreshesAuthenticatedAt(t *testing.T) {
	s, _, sessions, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	_, session, sessionTok, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Backdate the stamp directly in the store, as if this session had been
	// live for a while.
	old := time.Now().Add(-2 * time.Hour)
	sessions.mu.Lock()
	sessions.sessions[session.ID].AuthenticatedAt = old
	sessions.mu.Unlock()

	if err := s.ReAuthenticate(ctx, session, "password123", RequestInfo{}); err != nil {
		t.Fatalf("ReAuthenticate: %v", err)
	}

	// Same session, same token: ValidateSession still succeeds against the
	// original raw token.
	validated, _, err := s.ValidateSession(ctx, sessionTok)
	if err != nil {
		t.Fatalf("ValidateSession after ReAuthenticate: %v", err)
	}
	if validated.ID != session.ID {
		t.Fatalf("expected the same session ID %q, got %q — ReAuthenticate must not mint a new session", session.ID, validated.ID)
	}
	if !validated.AuthenticatedAt.After(old) {
		t.Fatalf("expected AuthenticatedAt refreshed after %v, got %v", old, validated.AuthenticatedAt)
	}
	// The passed-in *Session is also updated in place, so a caller need not
	// reload to see the refreshed stamp.
	if !session.AuthenticatedAt.After(old) {
		t.Fatalf("expected ReAuthenticate to update the caller's *Session in place, got %v", session.AuthenticatedAt)
	}
}

// TestReAuthenticateWrongPasswordDoesNotRefreshStamp asserts that a wrong
// password returns ErrInvalidCredentials and leaves AuthenticatedAt
// untouched.
func TestReAuthenticateWrongPasswordDoesNotRefreshStamp(t *testing.T) {
	s, _, sessions, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	_, session, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	old := time.Now().Add(-2 * time.Hour)
	sessions.mu.Lock()
	sessions.sessions[session.ID].AuthenticatedAt = old
	sessions.mu.Unlock()

	if err := s.ReAuthenticate(ctx, session, "wrong-password", RequestInfo{}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("ReAuthenticate error = %v, want ErrInvalidCredentials", err)
	}

	sessions.mu.Lock()
	got := sessions.sessions[session.ID].AuthenticatedAt
	sessions.mu.Unlock()
	if !got.Equal(old) {
		t.Fatalf("AuthenticatedAt changed on a failed ReAuthenticate: got %v, want unchanged %v", got, old)
	}
}

// TestReAuthenticatePasswordlessUserReturnsInvalidCredentials asserts that
// ReAuthenticate against a passwordless (magic-link-only) account fails the
// same way VerifyPassword does, via the dummy-hash timing-equalization path
// rather than an early return.
func TestReAuthenticatePasswordlessUserReturnsInvalidCredentials(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	rawToken, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	_, session, _, err := redeemMagicLink(t, s, ctx, rawToken)
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}

	if err := s.ReAuthenticate(ctx, session, "any-password", RequestInfo{}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("ReAuthenticate error = %v, want ErrInvalidCredentials", err)
	}
}

// TestReAuthenticateConsultsLimiter asserts that ReAuthenticate is
// rate-limited like VerifyPassword/ChangePassword: a denying limiter blocks
// it with ErrRateLimited, consulted with the "password:"+email key, before
// the password is ever verified.
func TestReAuthenticateConsultsLimiter(t *testing.T) {
	limiter := &fakeLimiter{}
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithLimiter(limiter))
	ctx := context.Background()

	_, session, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	limiter.mu.Lock()
	limiter.keys = nil
	limiter.denied = true
	limiter.mu.Unlock()

	err = s.ReAuthenticate(ctx, session, "definitely-wrong-password", RequestInfo{})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}

	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if len(limiter.keys) != 1 || limiter.keys[0] != "password:alice@example.com" {
		t.Fatalf("expected limiter consulted with key %q, got %v", "password:alice@example.com", limiter.keys)
	}
}

// TestCreateSessionRecordsAuthenticatedAtAndMethod asserts that every path
// that mints a session stamps AuthenticatedAt (recorded at issuance) and
// Method (which credential authenticated it).
func TestCreateSessionRecordsAuthenticatedAtAndMethod(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	before := time.Now()
	user, session, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if session.Method != AuthMethodPassword {
		t.Errorf("Register session Method = %q, want %q", session.Method, AuthMethodPassword)
	}
	if session.AuthenticatedAt.Before(before) {
		t.Errorf("Register session AuthenticatedAt = %v, want at or after %v", session.AuthenticatedAt, before)
	}

	verifyUserEmail(t, users, user.ID)
	loginRes, err := s.Login(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if loginRes.Session.Method != AuthMethodPassword {
		t.Errorf("Login session Method = %q, want %q", loginRes.Session.Method, AuthMethodPassword)
	}
	if loginRes.Session.AuthenticatedAt.IsZero() {
		t.Error("Login session AuthenticatedAt is zero")
	}

	unchecked, _, err := s.IssueSessionUnchecked(ctx, user.ID, AuthMethodPasskey)
	if err != nil {
		t.Fatalf("IssueSessionUnchecked: %v", err)
	}
	if unchecked.Method != AuthMethodPasskey {
		t.Errorf("IssueSessionUnchecked session Method = %q, want %q", unchecked.Method, AuthMethodPasskey)
	}
	if unchecked.AuthenticatedAt.IsZero() {
		t.Error("IssueSessionUnchecked session AuthenticatedAt is zero")
	}
}

// TestCompleteTwoFactorRecordsTwoFactorMethod asserts that a session minted
// via CompleteTwoFactor records AuthMethodTwoFactor, not the first factor's
// method.
func TestCompleteTwoFactorRecordsTwoFactorMethod(t *testing.T) {
	s, users, _, _, factors := newTestEnvWithFactors(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)
	factors.enroll(user.ID)

	res, err := s.Login(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !res.NeedsSecondFactor {
		t.Fatal("expected NeedsSecondFactor")
	}

	res2, err := s.CompleteTwoFactor(ctx, user.ID, res.PendingToken, RequestInfo{})
	if err != nil {
		t.Fatalf("CompleteTwoFactor: %v", err)
	}
	if res2.Session.Method != AuthMethodTwoFactor {
		t.Errorf("CompleteTwoFactor session Method = %q, want %q", res2.Session.Method, AuthMethodTwoFactor)
	}
}

// --- T502: Account disable and lockout ------------------------------------
//
// See status.go. The four required behaviors are covered by one test each:
// a disabled account cannot authenticate, an already-issued session dies
// via ValidateSession's own check the moment the account is disabled
// (isolated from DisableUser's session-revocation side effect below),
// a locked account recovers once LockedUntil passes, and DisableUser
// revokes every session. The optional automatic-lockout mechanism
// (WithFailureLockout) is covered separately further down.

// disableUserDirect stamps DisabledAt/DisabledReason on the stored user
// without calling DisableUser, so a test can isolate ValidateSession's own
// status check from DisableUser's session-revocation side effect.
func disableUserDirect(t *testing.T, users *memUserStore, userID, reason string) {
	t.Helper()
	ctx := context.Background()
	u, err := users.GetUserByID(ctx, userID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	now := time.Now()
	u.DisabledAt = &now
	u.DisabledReason = reason
	if err := users.UpdateUser(ctx, u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
}

// lockUserUntil stamps LockedUntil directly on the stored user, bypassing
// the automatic-lockout mechanism, so a test can pin the pure
// locked/expired check in isolation from whatever triggers a lock in
// practice.
func lockUserUntil(t *testing.T, users *memUserStore, userID string, until time.Time) {
	t.Helper()
	ctx := context.Background()
	u, err := users.GetUserByID(ctx, userID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	u.LockedUntil = &until
	if err := users.UpdateUser(ctx, u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
}

// TestDisableUserBlocksLogin asserts that Login for a disabled account fails
// with ErrAccountDisabled, carrying the ratified message
// "sulis: account disabled".
func TestDisableUserBlocksLogin(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	if err := s.DisableUser(ctx, user.ID, "reported for abuse"); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}

	_, err = s.Login(ctx, "alice@example.com", "password123", RequestInfo{})
	if !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("Login error = %v, want ErrAccountDisabled", err)
	}
	if err.Error() != "sulis: account disabled" {
		t.Fatalf("Login error message = %q, want %q", err.Error(), "sulis: account disabled")
	}
}

// TestValidateSessionRejectsDisabledAccountsExistingSession asserts that
// ValidateSession's own status check — not DisableUser's session
// revocation — is what kills a pre-existing session immediately once the
// account is disabled. DisabledAt is stamped directly here, bypassing
// DisableUser entirely, so the session this test validates was never
// touched by revocation; this is the isolation the T502 brief's mutation
// test ("remove the ValidateSession status check -> this test must fail")
// depends on.
func TestValidateSessionRejectsDisabledAccountsExistingSession(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, token, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	disableUserDirect(t, users, user.ID, "reported for abuse")

	if _, _, err := s.ValidateSession(ctx, token); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("ValidateSession error = %v, want ErrAccountDisabled", err)
	}
}

// TestDisableUserRevokesAllSessions asserts that DisableUser itself deletes
// every session belonging to the account, independent of ValidateSession's
// own check (proven separately above).
func TestDisableUserRevokesAllSessions(t *testing.T) {
	s, users, sessions, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)
	if _, _, err := s.IssueSessionUnchecked(ctx, user.ID, AuthMethodPassword); err != nil {
		t.Fatalf("IssueSessionUnchecked: %v", err)
	}
	if got := sessions.count(); got != 2 {
		t.Fatalf("sessions.count() before DisableUser = %d, want 2", got)
	}

	if err := s.DisableUser(ctx, user.ID, "reported for abuse"); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}

	if got := sessions.count(); got != 0 {
		t.Fatalf("sessions.count() after DisableUser = %d, want 0", got)
	}
}

// TestEnableUserRestoresLogin asserts that EnableUser reverses DisableUser:
// login works again, and DisabledAt/DisabledReason are cleared.
func TestEnableUserRestoresLogin(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	if err := s.DisableUser(ctx, user.ID, "reported for abuse"); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	if err := s.EnableUser(ctx, user.ID); err != nil {
		t.Fatalf("EnableUser: %v", err)
	}

	if _, err := s.Login(ctx, "alice@example.com", "password123", RequestInfo{}); err != nil {
		t.Fatalf("Login after EnableUser: %v", err)
	}

	after, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if after.DisabledAt != nil {
		t.Errorf("DisabledAt = %v, want nil after EnableUser", after.DisabledAt)
	}
	if after.DisabledReason != "" {
		t.Errorf("DisabledReason = %q, want empty after EnableUser", after.DisabledReason)
	}
}

// TestDisableUserUnknownUserReturnsErrUserNotFound and
// TestEnableUserUnknownUserReturnsErrUserNotFound pin the not-found case
// for both methods.
func TestDisableUserUnknownUserReturnsErrUserNotFound(t *testing.T) {
	s := newTestSulis()
	if err := s.DisableUser(context.Background(), "no-such-user", "reason"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("DisableUser error = %v, want ErrUserNotFound", err)
	}
}

func TestEnableUserUnknownUserReturnsErrUserNotFound(t *testing.T) {
	s := newTestSulis()
	if err := s.EnableUser(context.Background(), "no-such-user"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("EnableUser error = %v, want ErrUserNotFound", err)
	}
}

// TestAccountLockBlocksLoginUntilDeadlinePasses pins the pure
// locked/expired check: LockedUntil in the future blocks Login with
// ErrAccountLocked (message "sulis: account locked"); once the deadline is
// in the past, Login succeeds again with no explicit unlock call. LockedUntil
// is stamped directly, independent of whatever triggers a lock in practice
// (see the WithFailureLockout tests below for that), so this is the
// isolation the T502 brief's mutation test ("remove the lockout expiry
// check -> this test must fail") depends on.
func TestAccountLockBlocksLoginUntilDeadlinePasses(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	lockUserUntil(t, users, user.ID, time.Now().Add(time.Hour))

	_, err = s.Login(ctx, "alice@example.com", "password123", RequestInfo{})
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("Login error = %v, want ErrAccountLocked", err)
	}
	if err.Error() != "sulis: account locked" {
		t.Fatalf("Login error message = %q, want %q", err.Error(), "sulis: account locked")
	}

	lockUserUntil(t, users, user.ID, time.Now().Add(-time.Minute))

	if _, err := s.Login(ctx, "alice@example.com", "password123", RequestInfo{}); err != nil {
		t.Fatalf("Login after LockedUntil passed: %v", err)
	}
}

// TestVerifyPasswordChecksAccountStatusOnlyAfterPasswordVerifies pins the
// account-status oracle discipline the T502 brief demands: a wrong password
// against a disabled account returns the ordinary ErrInvalidCredentials,
// not ErrAccountDisabled, so a caller who has not proven the password
// cannot use the distinct error to learn that the account exists and is
// disabled.
func TestVerifyPasswordChecksAccountStatusOnlyAfterPasswordVerifies(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := s.DisableUser(ctx, user.ID, "reported for abuse"); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}

	_, err = s.VerifyPassword(ctx, "alice@example.com", "wrong-password", RequestInfo{})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("VerifyPassword with a wrong password for a disabled account error = %v, want ErrInvalidCredentials", err)
	}
	if errors.Is(err, ErrAccountDisabled) {
		t.Fatal("VerifyPassword leaked ErrAccountDisabled on a wrong password — this is the oracle the brief forbids")
	}
}

// TestCompleteTwoFactorRejectsDisabledAccount asserts that a pending
// two-factor login cannot be completed for an account disabled after the
// first factor was verified but before the second-factor step —
// CompleteTwoFactor mints a session directly (like completeFirstFactor and
// issueSessionForUser do) and so must be gated too, even though it is not
// named in the T502 brief's file list (see the T502 Decisions row).
func TestCompleteTwoFactorRejectsDisabledAccount(t *testing.T) {
	s, users, _, _, factors := newTestEnvWithFactors(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)
	factors.enroll(user.ID)

	res, err := s.Login(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !res.NeedsSecondFactor {
		t.Fatal("expected NeedsSecondFactor")
	}

	if err := s.DisableUser(ctx, user.ID, "reported for abuse"); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}

	if _, err := s.CompleteTwoFactor(ctx, user.ID, res.PendingToken, RequestInfo{}); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("CompleteTwoFactor error = %v, want ErrAccountDisabled", err)
	}
}

// TestIssueSessionUncheckedRejectsDisabledAccount asserts that the
// caller-vouches-for-it session-issuance primitive still refuses a
// disabled account — a caller vouching for a factor sulis doesn't verify
// itself must not be able to sidestep account status.
func TestIssueSessionUncheckedRejectsDisabledAccount(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	if err := s.DisableUser(ctx, user.ID, "reported for abuse"); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}

	if _, _, err := s.IssueSessionUnchecked(ctx, user.ID, AuthMethodPasskey); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("IssueSessionUnchecked error = %v, want ErrAccountDisabled", err)
	}
}

// TestRedeemMagicLinkRejectsDisabledAccount asserts that completeFirstFactor
// gates the magic-link path too, not only Login's password path — magic
// link redemption never calls VerifyPassword at all, so this is the only
// check that protects it.
func TestRedeemMagicLinkRejectsDisabledAccount(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	rawToken, err := s.CreateMagicLinkToken(ctx, "alice@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	if err := s.DisableUser(ctx, user.ID, "reported for abuse"); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}

	if _, err := s.RedeemMagicLink(ctx, rawToken, RequestInfo{}); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("RedeemMagicLink error = %v, want ErrAccountDisabled", err)
	}
}

// --- Optional automatic lockout (WithFailureLockout) ----------------------

// TestFailureLockoutDisabledByDefault asserts that a Sulis built with no
// options never locks an account no matter how many wrong passwords it
// sees — the feature is opt-in because an attacker-triggered lockout is
// itself a denial of service. Rate limiting is disabled here so the loop
// exercises VerifyPassword's own bookkeeping rather than tripping the
// (separate, on-by-default) limiter.
func TestFailureLockoutDisabledByDefault(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithoutRateLimiting())
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	for i := 0; i < 20; i++ {
		if _, err := s.VerifyPassword(ctx, "alice@example.com", "wrong-password", RequestInfo{}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: VerifyPassword error = %v, want ErrInvalidCredentials", i, err)
		}
	}

	after, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if after.FailedLoginAttempts != 0 {
		t.Errorf("FailedLoginAttempts = %d, want 0 with lockout disabled", after.FailedLoginAttempts)
	}
	if after.LockedUntil != nil {
		t.Errorf("LockedUntil = %v, want nil with lockout disabled", after.LockedUntil)
	}

	if _, err := s.VerifyPassword(ctx, "alice@example.com", "password123", RequestInfo{}); err != nil {
		t.Fatalf("VerifyPassword with the correct password after 20 failures: %v", err)
	}
}

// TestWithFailureLockoutLocksAfterThreshold drives the configured automatic
// lockout end to end: threshold consecutive wrong passwords set LockedUntil
// in the future and block even the correct password with ErrAccountLocked;
// once the window has passed (simulated by direct store manipulation rather
// than sleeping, for a deterministic test), the correct password both
// succeeds and clears the bookkeeping.
func TestWithFailureLockoutLocksAfterThreshold(t *testing.T) {
	s, users, _, _ := newTestEnv(
		WithArgon2Params(testArgon2Params),
		WithoutRateLimiting(),
		WithFailureLockout(3, 100*time.Millisecond, time.Second),
	)
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	for i := 0; i < 3; i++ {
		if _, err := s.VerifyPassword(ctx, "alice@example.com", "wrong-password", RequestInfo{}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: VerifyPassword error = %v, want ErrInvalidCredentials", i, err)
		}
	}

	after, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if after.FailedLoginAttempts != 3 {
		t.Fatalf("FailedLoginAttempts = %d, want 3", after.FailedLoginAttempts)
	}
	if after.LockedUntil == nil || !after.LockedUntil.After(time.Now()) {
		t.Fatalf("LockedUntil = %v, want a time in the future", after.LockedUntil)
	}

	// The correct password no longer authenticates immediately: the account
	// is locked until the backoff passes.
	if _, err := s.VerifyPassword(ctx, "alice@example.com", "password123", RequestInfo{}); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("VerifyPassword with the correct password while locked error = %v, want ErrAccountLocked", err)
	}

	// Fast-forward past the lockout window by direct store manipulation
	// (rather than sleeping) and confirm the correct password both succeeds
	// and clears the bookkeeping — no explicit unlock call exists or is
	// needed.
	lockUserUntil(t, users, user.ID, time.Now().Add(-time.Minute))

	if _, err := s.VerifyPassword(ctx, "alice@example.com", "password123", RequestInfo{}); err != nil {
		t.Fatalf("VerifyPassword after the lockout window: %v", err)
	}

	cleared, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if cleared.FailedLoginAttempts != 0 {
		t.Errorf("FailedLoginAttempts = %d, want 0 after a successful verification past the lockout window", cleared.FailedLoginAttempts)
	}
	if cleared.LockedUntil != nil {
		t.Errorf("LockedUntil = %v, want nil after a successful verification past the lockout window", cleared.LockedUntil)
	}
}

// TestLockoutBackoffGrowsExponentiallyAndCaps pins lockoutBackoff's pure
// math directly: base, doubling per excess failure, capped at max, with no
// overflow or negative result for an absurdly large excess.
func TestLockoutBackoffGrowsExponentiallyAndCaps(t *testing.T) {
	base := 100 * time.Millisecond
	max := time.Second
	cases := []struct {
		excess int
		want   time.Duration
	}{
		{0, 100 * time.Millisecond},
		{1, 200 * time.Millisecond},
		{2, 400 * time.Millisecond},
		{3, 800 * time.Millisecond},
		{4, time.Second},             // uncapped would be 1.6s; clamped to max
		{-1, 100 * time.Millisecond}, // negative excess clamps to 0
		{1000, time.Second},          // absurd excess still clamps, no overflow
	}
	for _, c := range cases {
		if got := lockoutBackoff(base, max, c.excess); got != c.want {
			t.Errorf("lockoutBackoff(%v, %v, %d) = %v, want %v", base, max, c.excess, got, c.want)
		}
	}
}

// --- T502 fix round 1: setPassword clears lockout, not disable -----------
//
// A successful password change or reset is at least as strong an identity
// proof as a correct login password, so it must clear an active automatic
// lockout the same way VerifyPassword's own success path does — otherwise
// an attacker can lock a victim out with nothing but repeated wrong
// guesses, and the victim's own reset (a stronger proof, via an out-of-band
// token) would not restore access until the backoff passed. DisabledAt is
// a distinct, operator-owned mechanism and must NOT be cleared this way.

// TestResetPasswordClearsLockoutButNotDisable covers ResetPassword, and
// pins the DisabledAt/LockedUntil distinction directly: the same account,
// first locked then disabled, has its lockout lifted by a reset but its
// disable survives one.
func TestResetPasswordClearsLockoutButNotDisable(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithoutRateLimiting())
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	u, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	until := time.Now().Add(time.Hour)
	u.LockedUntil = &until
	u.FailedLoginAttempts = 5
	if err := users.UpdateUser(ctx, u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	rawToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}
	if err := s.ResetPassword(ctx, rawToken, "newpassword123"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	// Login with the new password must succeed immediately — no
	// ErrAccountLocked left over from before the reset.
	if _, err := s.Login(ctx, "alice@example.com", "newpassword123", RequestInfo{}); err != nil {
		t.Fatalf("Login after ResetPassword: %v", err)
	}

	after, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if after.FailedLoginAttempts != 0 {
		t.Errorf("FailedLoginAttempts = %d, want 0 after ResetPassword", after.FailedLoginAttempts)
	}
	if after.LockedUntil != nil {
		t.Errorf("LockedUntil = %v, want nil after ResetPassword", after.LockedUntil)
	}

	// Now the distinction: DisableUser's stamp must survive a password
	// reset, because disabling is an operator action reversed only by
	// EnableUser — never by proving control of the password.
	if err := s.DisableUser(ctx, user.ID, "reported for abuse"); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	rawToken2, err := s.CreatePasswordResetToken(ctx, "alice@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreatePasswordResetToken (second): %v", err)
	}
	if err := s.ResetPassword(ctx, rawToken2, "anothernewpassword123"); err != nil {
		t.Fatalf("ResetPassword (second): %v", err)
	}
	_, err = s.Login(ctx, "alice@example.com", "anothernewpassword123", RequestInfo{})
	if !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("Login after a password reset on a disabled account error = %v, want ErrAccountDisabled", err)
	}
}

// TestChangePasswordClearsLockout covers ChangePassword: proving the old
// password clears an active lockout, exactly like VerifyPassword's own
// success path.
func TestChangePasswordClearsLockout(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithoutRateLimiting())
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	u, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	until := time.Now().Add(time.Hour)
	u.LockedUntil = &until
	u.FailedLoginAttempts = 5
	if err := users.UpdateUser(ctx, u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	if err := s.ChangePassword(ctx, user.ID, "password123", "newpassword123", RequestInfo{}); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	if _, err := s.Login(ctx, "alice@example.com", "newpassword123", RequestInfo{}); err != nil {
		t.Fatalf("Login after ChangePassword: %v", err)
	}

	after, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if after.FailedLoginAttempts != 0 {
		t.Errorf("FailedLoginAttempts = %d, want 0 after ChangePassword", after.FailedLoginAttempts)
	}
	if after.LockedUntil != nil {
		t.Errorf("LockedUntil = %v, want nil after ChangePassword", after.LockedUntil)
	}
}

// TestSetInitialPasswordClearsLockoutFields covers SetInitialPassword, the
// third setPassword caller. A passwordless account can't accumulate
// FailedLoginAttempts through ordinary use (VerifyPassword's dummy-hash
// branch for a passwordless user never calls recordFailedLogin), so this
// pins the clearing as a harmless no-op on the fields' zero values rather
// than a load-bearing recovery — set them directly to prove the write path
// still behaves correctly if they were ever non-zero.
func TestSetInitialPasswordClearsLockoutFields(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithoutRateLimiting())
	ctx := context.Background()

	rawToken, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	user, _, _, err := redeemMagicLink(t, s, ctx, rawToken)
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}

	u, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	until := time.Now().Add(time.Hour)
	u.LockedUntil = &until
	u.FailedLoginAttempts = 5
	if err := users.UpdateUser(ctx, u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	if err := s.SetInitialPassword(ctx, user.ID, "newpassword123"); err != nil {
		t.Fatalf("SetInitialPassword: %v", err)
	}

	if _, err := s.Login(ctx, "bob@example.com", "newpassword123", RequestInfo{}); err != nil {
		t.Fatalf("Login after SetInitialPassword: %v", err)
	}

	after, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if after.FailedLoginAttempts != 0 {
		t.Errorf("FailedLoginAttempts = %d, want 0 after SetInitialPassword", after.FailedLoginAttempts)
	}
	if after.LockedUntil != nil {
		t.Errorf("LockedUntil = %v, want nil after SetInitialPassword", after.LockedUntil)
	}
}
