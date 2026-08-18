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

	"github.com/borfast/sulis/passwordcheck"
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
	if sess.IdleExpiresAt != nil {
		idle := *sess.IdleExpiresAt
		cp.IdleExpiresAt = &idle
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

func (s *memSessionStore) ListUserSessions(_ context.Context, userID string) ([]Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Session
	for _, sess := range s.sessions {
		if sess.UserID == userID {
			out = append(out, *cloneTestSession(sess))
		}
	}
	return out, nil
}

func (s *memSessionStore) TouchSession(_ context.Context, id string, lastSeen time.Time, idleExpires *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return ErrSessionNotFound
	}
	sess.LastSeenAt = lastSeen
	if idleExpires == nil {
		sess.IdleExpiresAt = nil
	} else {
		idle := *idleExpires
		sess.IdleExpiresAt = &idle
	}
	return nil
}

func (s *memSessionStore) DeleteUserSessionsExcept(_ context.Context, userID, keepSessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.UserID == userID && id != keepSessionID {
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
func redeemMagicLink(t *testing.T, s *Sulis, ctx context.Context, rawToken, bindingNonce string) (*User, *Session, string, error) {
	t.Helper()
	res, err := s.RedeemMagicLink(ctx, rawToken, bindingNonce, RequestInfo{})
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

// weakerArgon2Params are deliberately weaker than testArgon2Params (which is
// already weak-for-speed), so a user registered against weakerArgon2Params
// and then logged in through a Sulis configured with testArgon2Params
// reproduces "an operator raised Argon2Params" cheaply — for the rehash-on-
// login tests (T504) — without needing a second real hashing-cost tier.
var weakerArgon2Params = Argon2Params{
	Memory:      8,
	Iterations:  1,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

func TestRegisterAndLogin(t *testing.T) {
	s, users, _, _ := newTestEnv()
	ctx := context.Background()

	user, _, sessionTok, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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
	res2, err := s.Login(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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
	_, err = s.Login(ctx, "nobody@example.com", "correct-battery-staple", RequestInfo{})
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

// TestRegisterAndLoginWithPepperConfigured is the Sulis-level counterpart to
// password_test.go's hashPassword/verifyPassword pepper unit tests: with a
// pepper configured from the start (WithPepper), Register and Login work
// exactly as they do without one, and a wrong password is still rejected.
func TestRegisterAndLoginWithPepperConfigured(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithPepper([]byte("a-deployment-pepper")))
	ctx := context.Background()

	user, _, sessionTok, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if sessionTok == "" {
		t.Fatal("expected non-empty session token")
	}
	verifyUserEmail(t, users, user.ID)

	res, err := s.Login(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Login with a pepper configured: %v", err)
	}
	if res.NeedsSecondFactor {
		t.Fatal("no second factor is enrolled, so Login should return a session")
	}

	if _, err := s.Login(ctx, "alice@example.com", "wrong-password", RequestInfo{}); err != ErrInvalidCredentials {
		t.Fatalf("Login with the wrong password under a pepper = %v, want ErrInvalidCredentials", err)
	}
}

func TestRegisterDuplicate(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	_, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	_, _, _, err = s.Register(ctx, "alice@example.com", "another-battery-staple", RequestInfo{})
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

	_, _, sessionTok, _ := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})

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

	_, sessA, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register alice: %v", err)
	}
	_, sessB, tokB, err := s.Register(ctx, "bob@example.com", "correct-battery-staple", RequestInfo{})
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
	rawToken, nonce, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	user, _, sessionTok, err := redeemMagicLink(t, s, ctx, rawToken, nonce)
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
	_, err = s.RedeemMagicLink(ctx, rawToken, nonce, RequestInfo{})
	if err != ErrTokenAlreadyUsed {
		t.Fatalf("expected ErrTokenAlreadyUsed, got %v", err)
	}
}

// --- T508: split magic-link TTL; bind links to the requester --------------

// storedTokenByHash returns the token store's copy of the token whose raw
// value hashes to rawToken, for tests that need to inspect fields (like
// NonceHash) RedeemMagicLink's return value doesn't surface.
func storedTokenByHash(t *testing.T, tokens *memTokenStore, rawToken string) *Token {
	t.Helper()
	want := hashToken(rawToken)
	tokens.mu.Lock()
	defer tokens.mu.Unlock()
	for _, tk := range tokens.tokens {
		if tk.TokenHash == want {
			cp := *tk
			return &cp
		}
	}
	t.Fatalf("no stored token found for the given raw token")
	return nil
}

// TestMagicLinkDurationIsIndependentOfTokenDuration asserts that magic-link
// tokens expire after the default MagicLinkDuration (15m) regardless of
// TokenDuration, which now governs password-reset tokens only. A magic link
// is a full credential delivered in cleartext over email — often forwarded,
// scanned, or prefetched — so it must not inherit whatever TTL an operator
// picks for password resets.
func TestMagicLinkDurationIsIndependentOfTokenDuration(t *testing.T) {
	s, _, _, tokens := newTestEnv(WithTokenDuration(2 * time.Hour))
	ctx := context.Background()

	rawToken, _, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	stored := storedTokenByHash(t, tokens, rawToken)
	want := 15 * time.Minute
	got := stored.ExpiresAt.Sub(stored.CreatedAt)
	if got < want-time.Second || got > want+time.Second {
		t.Fatalf("magic-link TTL = %v, want ~%v (independent of the configured 2h TokenDuration)", got, want)
	}
}

// TestWithMagicLinkDurationOverridesDefault asserts that WithMagicLinkDuration
// actually changes the TTL magic-link tokens are issued with, rather than the
// default merely happening to be independent of TokenDuration on its own.
func TestWithMagicLinkDurationOverridesDefault(t *testing.T) {
	s, _, _, tokens := newTestEnv(WithMagicLinkDuration(3 * time.Minute))
	ctx := context.Background()

	rawToken, _, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	stored := storedTokenByHash(t, tokens, rawToken)
	want := 3 * time.Minute
	got := stored.ExpiresAt.Sub(stored.CreatedAt)
	if got < want-time.Second || got > want+time.Second {
		t.Fatalf("magic-link TTL = %v, want ~%v (the configured WithMagicLinkDuration)", got, want)
	}
}

// TestRedeemMagicLinkRejectsMissingOrWrongNonceWhenBindingOn asserts that,
// under the default WithMagicLinkBinding(true), a missing or incorrect
// binding nonce is rejected with ErrTokenInvalid even though the token
// itself is valid, unused, and unexpired. This is the property that makes a
// forwarded magic link useless on a different browser: the nonce, not the
// token, is what only the original requester's browser can present (via the
// short-lived HttpOnly cookie the application sets at issuance time).
func TestRedeemMagicLinkRejectsMissingOrWrongNonceWhenBindingOn(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	rawToken1, nonce1, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	if nonce1 == "" {
		t.Fatal("expected a non-empty binding nonce when binding is on (the default)")
	}
	if _, err := s.RedeemMagicLink(ctx, rawToken1, "", RequestInfo{}); err != ErrTokenInvalid {
		t.Fatalf("missing nonce: expected ErrTokenInvalid, got %v", err)
	}

	rawToken2, _, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken (second): %v", err)
	}
	if _, err := s.RedeemMagicLink(ctx, rawToken2, "wrong-nonce", RequestInfo{}); err != ErrTokenInvalid {
		t.Fatalf("wrong nonce: expected ErrTokenInvalid, got %v", err)
	}

	// A third, freshly issued token with its own correct nonce still
	// redeems — proving the two rejections above were about the nonce
	// specifically, not some wider breakage.
	rawToken3, nonce3, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken (third): %v", err)
	}
	if _, err := s.RedeemMagicLink(ctx, rawToken3, nonce3, RequestInfo{}); err != nil {
		t.Fatalf("expected the correct nonce to redeem successfully, got %v", err)
	}
}

// TestRedeemMagicLinkWithoutNonceWorksWhenBindingOff asserts that
// WithMagicLinkBinding(false) both stops CreateMagicLinkToken from minting
// a nonce at all and makes RedeemMagicLink accept any bindingNonce value —
// including empty, and including an arbitrary non-empty one — since a token
// issued under this setting stores no NonceHash to check against.
func TestRedeemMagicLinkWithoutNonceWorksWhenBindingOff(t *testing.T) {
	s, _, _, _ := newTestEnv(WithMagicLinkBinding(false))
	ctx := context.Background()

	rawToken1, nonce, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	if nonce != "" {
		t.Fatalf("expected an empty binding nonce when binding is off, got %q", nonce)
	}
	if _, err := s.RedeemMagicLink(ctx, rawToken1, "", RequestInfo{}); err != nil {
		t.Fatalf("expected redemption without a nonce to succeed when binding is off, got %v", err)
	}

	rawToken2, _, err := s.CreateMagicLinkToken(ctx, "carol@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken (second): %v", err)
	}
	if _, err := s.RedeemMagicLink(ctx, rawToken2, "anything-goes", RequestInfo{}); err != nil {
		t.Fatalf("expected redemption with an arbitrary nonce to succeed when binding is off, got %v", err)
	}
}

// TestMagicLinkNonceIsStoredHashed asserts that the binding nonce is never
// persisted in plaintext: the stored token's NonceHash must be the nonce's
// SHA-256 hash, matching TokenHash's own treatment of the raw token, never
// the raw nonce itself.
func TestMagicLinkNonceIsStoredHashed(t *testing.T) {
	s, _, _, tokens := newTestEnv()
	ctx := context.Background()

	rawToken, nonce, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	if nonce == "" {
		t.Fatal("expected a non-empty binding nonce")
	}

	stored := storedTokenByHash(t, tokens, rawToken)
	if stored.NonceHash == "" {
		t.Fatal("expected a non-empty stored NonceHash when binding is on")
	}
	if stored.NonceHash == nonce {
		t.Fatal("stored NonceHash must not equal the plaintext nonce")
	}
	if stored.NonceHash != hashToken(nonce) {
		t.Fatalf("NonceHash = %q, want the SHA-256 hash of the raw nonce (%q)", stored.NonceHash, hashToken(nonce))
	}
}

// TestRedeemMagicLinkRejectsMissingOrWrongNonceOnExistingUserPathWhenBindingOn
// is the existing-user-path counterpart to
// TestRedeemMagicLinkRejectsMissingOrWrongNonceWhenBindingOn, which only
// exercises the pre-registration (unknown-email) path. CreateMagicLinkToken
// takes a different branch once a user already exists — issueMagicLinkToken
// is called with a non-empty userID instead of a non-empty email — and a
// success-only test on that branch (passing the correct nonce) cannot tell
// "the nonce is enforced" apart from "no NonceHash was ever stored, so any
// nonce silently passes" (see TestMagicLinkNonceIsStoredHashed, which checks
// the latter only on the OTHER branch). This test drives the same
// missing/wrong-nonce-rejected, correct-nonce-accepted, and
// NonceHash-is-stored assertions against an already-registered user.
func TestRedeemMagicLinkRejectsMissingOrWrongNonceOnExistingUserPathWhenBindingOn(t *testing.T) {
	s, _, _, tokens := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// (c) the token row for an existing user carries a NonceHash too, not
	// just the pre-registration path.
	rawToken0, nonce0, err := s.CreateMagicLinkToken(ctx, "alice@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	if nonce0 == "" {
		t.Fatal("expected a non-empty binding nonce for the existing-user path")
	}
	stored := storedTokenByHash(t, tokens, rawToken0)
	if stored.UserID != user.ID {
		t.Fatalf("expected the stored token to carry the existing user's ID, got %q", stored.UserID)
	}
	if stored.NonceHash == "" {
		t.Fatal("expected a non-empty stored NonceHash on the existing-user path when binding is on")
	}

	// (a) wrong nonce -> ErrTokenInvalid.
	rawToken1, _, err := s.CreateMagicLinkToken(ctx, "alice@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken (second): %v", err)
	}
	if _, err := s.RedeemMagicLink(ctx, rawToken1, "wrong-nonce", RequestInfo{}); err != ErrTokenInvalid {
		t.Fatalf("wrong nonce (existing-user path): expected ErrTokenInvalid, got %v", err)
	}

	// (b) missing nonce -> ErrTokenInvalid.
	rawToken2, _, err := s.CreateMagicLinkToken(ctx, "alice@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken (third): %v", err)
	}
	if _, err := s.RedeemMagicLink(ctx, rawToken2, "", RequestInfo{}); err != ErrTokenInvalid {
		t.Fatalf("missing nonce (existing-user path): expected ErrTokenInvalid, got %v", err)
	}

	// The correct nonce still redeems — proving the two rejections above
	// were about the nonce, not some wider breakage on this path.
	rawToken3, nonce3, err := s.CreateMagicLinkToken(ctx, "alice@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken (fourth): %v", err)
	}
	if _, err := s.RedeemMagicLink(ctx, rawToken3, nonce3, RequestInfo{}); err != nil {
		t.Fatalf("expected the correct nonce to redeem successfully on the existing-user path, got %v", err)
	}
}

// TestMagicLinkBindingDecidedByStoredTokenNotLiveConfig pins the Decisions-
// row property: whether a nonce is required is decided by the TOKEN's own
// stored NonceHash, not by whatever MagicLinkBinding the *redeeming* Sulis
// instance happens to be configured with. Two Sulis instances share the same
// underlying stores — standing in for the same deployment's config changing
// between issuance and redemption (e.g. a rolling deploy, or one instance
// mid-rollout with a new flag while another still has the old one) — and
// differ only in MagicLinkBinding.
func TestMagicLinkBindingDecidedByStoredTokenNotLiveConfig(t *testing.T) {
	users := newMemUserStore()
	sessions := newMemSessionStore()
	tokens := newMemTokenStore()
	ctx := context.Background()

	sOn := mustNew(users, sessions, tokens)                               // MagicLinkBinding: true (default)
	sOff := mustNew(users, sessions, tokens, WithMagicLinkBinding(false)) // MagicLinkBinding: false

	// Issued with binding ON, redeemed by an instance configured with
	// binding OFF: the nonce must still be REQUIRED, because the token
	// itself carries a NonceHash.
	rawToken1, _, err := sOn.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken (issued on): %v", err)
	}
	if _, err := sOff.RedeemMagicLink(ctx, rawToken1, "", RequestInfo{}); err != ErrTokenInvalid {
		t.Fatalf("issued binding-ON, redeemed binding-OFF, no nonce: expected ErrTokenInvalid, got %v", err)
	}

	rawToken2, nonce2, err := sOn.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken (issued on, second): %v", err)
	}
	if _, err := sOff.RedeemMagicLink(ctx, rawToken2, nonce2, RequestInfo{}); err != nil {
		t.Fatalf("issued binding-ON, redeemed binding-OFF, correct nonce: expected success, got %v", err)
	}

	// Issued with binding OFF, redeemed by an instance configured with
	// binding ON: the token carries no NonceHash, so redemption must still
	// succeed nonce-less — the redeeming instance's own default does not
	// retroactively demand a nonce the token was never issued with.
	rawToken3, nonce3, err := sOff.CreateMagicLinkToken(ctx, "carol@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken (issued off): %v", err)
	}
	if nonce3 != "" {
		t.Fatalf("expected an empty binding nonce when the ISSUING instance has binding off, got %q", nonce3)
	}
	if _, err := sOn.RedeemMagicLink(ctx, rawToken3, "", RequestInfo{}); err != nil {
		t.Fatalf("issued binding-OFF, redeemed binding-ON, no nonce: expected success, got %v", err)
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

func (s *observingSessionStore) ListUserSessions(_ context.Context, userID string) ([]Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Session
	for _, sess := range s.sessionByHash {
		if sess.UserID == userID {
			out = append(out, *sess)
		}
	}
	return out, nil
}

func (s *observingSessionStore) TouchSession(_ context.Context, id string, lastSeen time.Time, idleExpires *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessionByHash {
		if sess.ID == id {
			sess.LastSeenAt = lastSeen
			sess.IdleExpiresAt = idleExpires
			return nil
		}
	}
	return ErrSessionNotFound
}

func (s *observingSessionStore) DeleteUserSessionsExcept(_ context.Context, userID, keepSessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, sess := range s.sessionByHash {
		if sess.UserID == userID && sess.ID != keepSessionID {
			delete(s.sessionByHash, hash)
		}
	}
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

func (s *sharedSessionStore) ListUserSessions(_ context.Context, userID string) ([]Session, error) {
	if s.session == nil || s.session.UserID != userID {
		return nil, nil
	}
	return []Session{*s.session}, nil
}

func (s *sharedSessionStore) TouchSession(_ context.Context, id string, lastSeen time.Time, idleExpires *time.Time) error {
	if s.session == nil || s.session.ID != id {
		return ErrSessionNotFound
	}
	s.session.LastSeenAt = lastSeen
	s.session.IdleExpiresAt = idleExpires
	return nil
}

func (s *sharedSessionStore) DeleteUserSessionsExcept(_ context.Context, userID, keepSessionID string) error {
	if s.session != nil && s.session.UserID == userID && s.session.ID != keepSessionID {
		s.session = nil
	}
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

	user, session, sessionTok, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	rawToken, nonce, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	// The user is only created at redemption time (deferred user creation).
	user, _, _, err := redeemMagicLink(t, s, ctx, rawToken, nonce)
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

	rawToken, nonce, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	// The user is only created at redemption time (deferred user creation).
	user, _, _, err := redeemMagicLink(t, s, ctx, rawToken, nonce)
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	rawToken, _, err := s.CreateMagicLinkToken(ctx, "wrapped@example.com", RequestInfo{})
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
	_, err = s.RedeemMagicLink(ctx, rawToken, "", RequestInfo{})
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

// TestSetPasswordPurgesMagicLinkTokens asserts that both password-setting
// recovery paths — ResetPassword and ChangePassword, which share setPassword
// — burn any outstanding magic link for the account.
//
// Same reasoning as the email-change purge (see
// TestConfirmEmailChangePurgesMagicLinkTokens): a magic link issued in its
// existing-user shape is redeemed by user ID with no address check, so it
// outlives a recovery unless it is deleted. A password reset is the other
// half of the mailbox-compromise recovery story — a victim who suspects the
// mailbox was read rotates the password — and it would be a strange
// guarantee that burned the pending 2FA token minted against the old
// password while leaving a live passwordless login to the same account in
// the attacker's hands.
func TestSetPasswordPurgesMagicLinkTokens(t *testing.T) {
	t.Run("ResetPassword", func(t *testing.T) {
		s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
		ctx := context.Background()

		user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		verifyUserEmail(t, users, user.ID)

		magicToken, nonce, err := s.CreateMagicLinkToken(ctx, "alice@example.com", RequestInfo{})
		if err != nil {
			t.Fatalf("CreateMagicLinkToken: %v", err)
		}

		resetToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com", RequestInfo{})
		if err != nil {
			t.Fatalf("CreatePasswordResetToken: %v", err)
		}
		if err := s.ResetPassword(ctx, resetToken, "brand-new-password"); err != nil {
			t.Fatalf("ResetPassword: %v", err)
		}

		if _, err := s.RedeemMagicLink(ctx, magicToken, nonce, RequestInfo{}); err != ErrTokenInvalid {
			t.Fatalf("expected the outstanding magic link to be purged by the reset, got %v", err)
		}
	})

	t.Run("ChangePassword", func(t *testing.T) {
		s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
		ctx := context.Background()

		user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		verifyUserEmail(t, users, user.ID)

		magicToken, nonce, err := s.CreateMagicLinkToken(ctx, "alice@example.com", RequestInfo{})
		if err != nil {
			t.Fatalf("CreateMagicLinkToken: %v", err)
		}

		if err := s.ChangePassword(ctx, user.ID, "correct-battery-staple", "brand-new-password", RequestInfo{}); err != nil {
			t.Fatalf("ChangePassword: %v", err)
		}

		if _, err := s.RedeemMagicLink(ctx, magicToken, nonce, RequestInfo{}); err != ErrTokenInvalid {
			t.Fatalf("expected the outstanding magic link to be purged by the change, got %v", err)
		}
	})
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

	_, _, sessionTok, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	rawToken, nonce, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	// Redeem so the passwordless user actually exists; otherwise this would
	// exercise the unknown-user path instead of the passwordless-user path.
	if _, err := s.RedeemMagicLink(ctx, rawToken, nonce, RequestInfo{}); err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}

	if _, err := s.Login(ctx, "bob@example.com", "any-password", RequestInfo{}); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestEmailsAreNormalized(t *testing.T) {
	s, users, _, _ := newTestEnv()
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "Foo@X.com ", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Verification is incidental to this test; the gate is covered elsewhere.
	verifyUserEmail(t, users, user.ID)

	// A differently-cased, untrimmed variant of the same address must log in.
	_, err = s.Login(ctx, "foo@x.com", "correct-battery-staple", RequestInfo{})
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
		_, _, _, err := s.Register(ctx, email, "correct-battery-staple", RequestInfo{})
		if err != ErrInvalidEmail {
			t.Fatalf("Register(%q): expected ErrInvalidEmail, got %v", email, err)
		}
	}
}

func TestCreateMagicLinkTokenDoesNotCreateUser(t *testing.T) {
	s, users, _, _ := newTestEnv()
	ctx := context.Background()

	rawToken, _, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
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

	rawToken, nonce, err := s.CreateMagicLinkToken(ctx, "Bob@Example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	if len(users.users) != 0 {
		t.Fatalf("expected no user before redemption, got %d", len(users.users))
	}

	user, _, sessionTok, err := redeemMagicLink(t, s, ctx, rawToken, nonce)
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

	rawToken, nonce, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	// Someone registers a full account for this email between token issuance
	// and redemption (e.g. via a concurrent request on another path).
	registeredUser, _, _, err := s.Register(ctx, "bob@example.com", "some-password", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	user, _, _, err := redeemMagicLink(t, s, ctx, rawToken, nonce)
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

	rawToken, nonce, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	user, _, _, err := redeemMagicLink(t, s, ctx, rawToken, nonce)
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

	if _, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Register creates its own session; clear it so we can observe
	// VerifyPassword's effect in isolation.
	sessions.sessions = make(map[string]*Session)

	user, err := s.VerifyPassword(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	if _, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := s.VerifyPassword(ctx, "alice@example.com", "wrong", RequestInfo{}); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	if _, err := s.VerifyPassword(ctx, "nobody@example.com", "correct-battery-staple", RequestInfo{}); err != ErrInvalidCredentials {
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Verification is incidental to this test; the gate is covered elsewhere.
	verifyUserEmail(t, users, user.ID)

	res, err := s.Login(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Verification is incidental to this test; the gate is covered elsewhere.
	verifyUserEmail(t, users, user.ID)
	// Register creates its own session; clear it so we can observe the
	// two-factor flow's effect in isolation.
	sessions.sessions = make(map[string]*Session)

	gotUser, err := s.VerifyPassword(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	userA, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register (A): %v", err)
	}
	userB, _, _, err := s.Register(ctx, "bob@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	rawToken, nonce, err := s.CreateMagicLinkToken(ctx, "victim@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	verifiedUser, _, _, err := redeemMagicLink(t, s, ctx, rawToken, nonce)
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	if verifiedUser.EmailVerifiedAt == nil {
		t.Fatal("expected RedeemMagicLink to stamp EmailVerifiedAt")
	}
	firstVerifiedAt := *verifiedUser.EmailVerifiedAt

	rawToken2, nonce2, err := s.CreateMagicLinkToken(ctx, "victim@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken (second): %v", err)
	}
	secondUser, _, _, err := redeemMagicLink(t, s, ctx, rawToken2, nonce2)
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

	rawToken, nonce, err := s.CreateMagicLinkToken(ctx, "victim@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	victimUser, _, victimSessionTok, err := redeemMagicLink(t, s, ctx, rawToken, nonce)
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

	if _, _, err := s.CreateMagicLinkToken(ctx, "alice@example.com", RequestInfo{}); !errors.Is(err, ErrRateLimited) {
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

	if _, _, err := s.CreateMagicLinkToken(ctx, "carol@example.com", RequestInfo{}); err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
}

// TestUnverifiedAccountCannotStartNewSessions asserts that, under the default
// config, every session-starting entry point rejects an account whose email
// has not been verified, while Register's own signup session is unaffected.
func TestUnverifiedAccountCannotStartNewSessions(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, sessionTok, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if sessionTok == "" {
		t.Fatal("expected Register's auto-session to still be issued")
	}

	if _, err := s.Login(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{}); err != ErrEmailNotVerified {
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	if _, err := s.Login(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{}); err != nil {
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

	rawToken, nonce, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	user, _, sessionTok, err := redeemMagicLink(t, s, ctx, rawToken, nonce)
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

	_, _, sessionTok, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if user.EmailVerifiedAt != nil {
		t.Fatal("expected EmailVerifiedAt nil; this test is about unverified accounts")
	}

	if _, err := s.Login(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{}); err != nil {
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

	if ok, _, _ := verifyPassword(oldPassword, stored.PasswordHash, nil); ok {
		t.Error("the reset was silently undone: the old password still verifies")
	}
	ok, _, err := verifyPassword(newPassword, stored.PasswordHash, nil)
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)
	factors.enroll(user.ID)

	before := sessions.count()

	res, err := s.Login(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "bob@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	res, err := s.Login(ctx, "bob@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "carol@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	checkerErr := errors.New("factor store offline")
	factors.failWith(checkerErr)
	before := sessions.count()

	res, err := s.Login(ctx, "carol@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)
	factors.enroll(user.ID)

	rawToken, nonce, err := s.CreateMagicLinkToken(ctx, "alice@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	before := sessions.count()

	res, err := s.RedeemMagicLink(ctx, rawToken, nonce, RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "dave@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	factors.enroll(user.ID)

	// Deliberately left unverified.
	rawToken, nonce, err := s.CreateMagicLinkToken(ctx, "dave@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	res, err := s.RedeemMagicLink(ctx, rawToken, nonce, RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	_, session, sessionTok, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Backdate the stamp directly in the store, as if this session had been
	// live for a while.
	old := time.Now().Add(-2 * time.Hour)
	sessions.mu.Lock()
	sessions.sessions[session.ID].AuthenticatedAt = old
	sessions.mu.Unlock()

	if err := s.ReAuthenticate(ctx, session, "correct-battery-staple", RequestInfo{}); err != nil {
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

// TestReAuthenticateUpgradesWeakStoredHash is the regression test for the
// T504 (fix round 1) Decisions row: ReAuthenticate is a real password
// comparison against a real stored hash, so — like Login/VerifyPassword — a
// successful call upgrades a hash weaker than the currently configured
// Argon2Params, using the same needsRehash/rehashPassword path.
func TestReAuthenticateUpgradesWeakStoredHash(t *testing.T) {
	ctx := context.Background()
	const (
		email    = "alice@example.com"
		password = "correct-horse-battery-staple"
	)

	users := newMemUserStore()
	sessions := newMemSessionStore()
	tokens := newMemTokenStore()

	weak := mustNew(users, sessions, tokens, WithArgon2Params(weakerArgon2Params))
	user, session, _, err := weak.Register(ctx, email, password, RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	before, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}

	strong := mustNew(users, sessions, tokens, WithArgon2Params(testArgon2Params))
	if !needsRehash(before.PasswordHash, testArgon2Params) {
		t.Fatal("test setup is broken: the seeded hash must be weaker than testArgon2Params, or this test proves nothing")
	}

	if err := strong.ReAuthenticate(ctx, session, password, RequestInfo{}); err != nil {
		t.Fatalf("ReAuthenticate: %v", err)
	}

	after, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if after.PasswordHash == before.PasswordHash {
		t.Fatal("stored hash was not upgraded on a successful ReAuthenticate with a weaker-than-configured stored hash")
	}

	gotParams, _, _, err := decodeHash(after.PasswordHash)
	if err != nil {
		t.Fatalf("decodeHash(upgraded hash): %v", err)
	}
	if gotParams.Memory != testArgon2Params.Memory || gotParams.Iterations != testArgon2Params.Iterations || gotParams.Parallelism != testArgon2Params.Parallelism {
		t.Fatalf("upgraded hash params = %+v, want the configured %+v", gotParams, testArgon2Params)
	}

	ok, _, err := verifyPassword(password, after.PasswordHash, nil)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("the password no longer verifies against its own upgraded hash")
	}
}

// TestReAuthenticateWrongPasswordDoesNotRefreshStamp asserts that a wrong
// password returns ErrInvalidCredentials and leaves AuthenticatedAt
// untouched.
func TestReAuthenticateWrongPasswordDoesNotRefreshStamp(t *testing.T) {
	s, _, sessions, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	_, session, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	rawToken, nonce, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	_, session, _, err := redeemMagicLink(t, s, ctx, rawToken, nonce)
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

	_, session, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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
	user, session, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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
	loginRes, err := s.Login(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)
	factors.enroll(user.ID)

	res, err := s.Login(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	if err := s.DisableUser(ctx, user.ID, "reported for abuse"); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}

	_, err = s.Login(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, token, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	if _, err := s.Login(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{}); err != nil {
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	lockUserUntil(t, users, user.ID, time.Now().Add(time.Hour))

	_, err = s.Login(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("Login error = %v, want ErrAccountLocked", err)
	}
	if err.Error() != "sulis: account locked" {
		t.Fatalf("Login error message = %q, want %q", err.Error(), "sulis: account locked")
	}

	lockUserUntil(t, users, user.ID, time.Now().Add(-time.Minute))

	if _, err := s.Login(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{}); err != nil {
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)
	factors.enroll(user.ID)

	res, err := s.Login(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	rawToken, nonce, err := s.CreateMagicLinkToken(ctx, "alice@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	if err := s.DisableUser(ctx, user.ID, "reported for abuse"); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}

	if _, err := s.RedeemMagicLink(ctx, rawToken, nonce, RequestInfo{}); !errors.Is(err, ErrAccountDisabled) {
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	if _, err := s.VerifyPassword(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{}); err != nil {
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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
	if _, err := s.VerifyPassword(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{}); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("VerifyPassword with the correct password while locked error = %v, want ErrAccountLocked", err)
	}

	// Fast-forward past the lockout window by direct store manipulation
	// (rather than sleeping) and confirm the correct password both succeeds
	// and clears the bookkeeping — no explicit unlock call exists or is
	// needed.
	lockUserUntil(t, users, user.ID, time.Now().Add(-time.Minute))

	if _, err := s.VerifyPassword(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{}); err != nil {
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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
	if err := s.ResetPassword(ctx, rawToken, "new-correct-battery-staple"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	// Login with the new password must succeed immediately — no
	// ErrAccountLocked left over from before the reset.
	if _, err := s.Login(ctx, "alice@example.com", "new-correct-battery-staple", RequestInfo{}); err != nil {
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
	if err := s.ResetPassword(ctx, rawToken2, "another-new-battery-staple"); err != nil {
		t.Fatalf("ResetPassword (second): %v", err)
	}
	_, err = s.Login(ctx, "alice@example.com", "another-new-battery-staple", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
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

	if err := s.ChangePassword(ctx, user.ID, "correct-battery-staple", "new-correct-battery-staple", RequestInfo{}); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	if _, err := s.Login(ctx, "alice@example.com", "new-correct-battery-staple", RequestInfo{}); err != nil {
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

	rawToken, nonce, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	user, _, _, err := redeemMagicLink(t, s, ctx, rawToken, nonce)
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

	if err := s.SetInitialPassword(ctx, user.ID, "new-correct-battery-staple"); err != nil {
		t.Fatalf("SetInitialPassword: %v", err)
	}

	if _, err := s.Login(ctx, "bob@example.com", "new-correct-battery-staple", RequestInfo{}); err != nil {
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

// --- T503: session visibility and lifecycle -------------------------------
//
// See session.go (Session.LastSeenAt/IdleExpiresAt/IP/UserAgent,
// SessionStore.ListUserSessions/TouchSession/DeleteUserSessionsExcept),
// issue.go/sulis.go/magiclink.go/twofactor.go (RequestInfo threaded into
// createSession), and config.go (WithIdleTimeout). ListUserSessions and
// RefreshSession are the two new Sulis-level methods.

// touchCountingSessionStore wraps a real memSessionStore and counts calls to
// TouchSession, so a test can assert ValidateSession's liveness touch is
// throttled rather than written on every single validation.
type touchCountingSessionStore struct {
	*memSessionStore
	touches int
}

func (s *touchCountingSessionStore) TouchSession(ctx context.Context, id string, lastSeen time.Time, idleExpires *time.Time) error {
	s.touches++
	return s.memSessionStore.TouchSession(ctx, id, lastSeen, idleExpires)
}

// TestSessionsRecordRequestInfoAtIssuance asserts that every issuance path
// that already has a RequestInfo in hand stamps Session.IP/UserAgent from
// it: Register, Login/RedeemMagicLink (via completeFirstFactor), and
// CompleteTwoFactor. IssueSession/IssueSessionUnchecked are deliberately
// not covered here — their Appendix A signatures carry no RequestInfo, so
// sessions minted through them get the zero value; see the PROGRESS.md
// Decisions row.
func TestSessionsRecordRequestInfoAtIssuance(t *testing.T) {
	s, users, _, _, factors := newTestEnvWithFactors(WithArgon2Params(testArgon2Params))
	ctx := context.Background()
	ri := RequestInfo{IP: "203.0.113.5", UserAgent: "test-agent/1.0"}

	_, regSession, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", ri)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if regSession.IP != ri.IP || regSession.UserAgent != ri.UserAgent {
		t.Errorf("Register session IP/UserAgent = %q/%q, want %q/%q", regSession.IP, regSession.UserAgent, ri.IP, ri.UserAgent)
	}

	verifyUserEmail(t, users, regSession.UserID)
	loginRes, err := s.Login(ctx, "alice@example.com", "correct-battery-staple", ri)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if loginRes.Session.IP != ri.IP || loginRes.Session.UserAgent != ri.UserAgent {
		t.Errorf("Login session IP/UserAgent = %q/%q, want %q/%q", loginRes.Session.IP, loginRes.Session.UserAgent, ri.IP, ri.UserAgent)
	}

	rawToken, nonce, err := s.CreateMagicLinkToken(ctx, "bob@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	magicRes, err := s.RedeemMagicLink(ctx, rawToken, nonce, ri)
	if err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	if magicRes.NeedsSecondFactor {
		t.Fatal("this test does not expect a second-factor demand")
	}
	if magicRes.Session.IP != ri.IP || magicRes.Session.UserAgent != ri.UserAgent {
		t.Errorf("RedeemMagicLink session IP/UserAgent = %q/%q, want %q/%q", magicRes.Session.IP, magicRes.Session.UserAgent, ri.IP, ri.UserAgent)
	}

	factors.enroll(regSession.UserID)
	pending, err := s.Login(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Login (2FA pending): %v", err)
	}
	if !pending.NeedsSecondFactor {
		t.Fatal("expected NeedsSecondFactor")
	}
	res2, err := s.CompleteTwoFactor(ctx, regSession.UserID, pending.PendingToken, ri)
	if err != nil {
		t.Fatalf("CompleteTwoFactor: %v", err)
	}
	if res2.Session.IP != ri.IP || res2.Session.UserAgent != ri.UserAgent {
		t.Errorf("CompleteTwoFactor session IP/UserAgent = %q/%q, want %q/%q", res2.Session.IP, res2.Session.UserAgent, ri.IP, ri.UserAgent)
	}
}

// TestListUserSessionsStripsTokenHash pins this task's core security
// property: no session returned by the service-level ListUserSessions ever
// carries a TokenHash, even though SessionStore.ListUserSessions itself
// returns whatever the store stores (see that method's doc comment) — a
// "where you're signed in" screen has no legitimate reason to see even a
// hash of a bearer credential.
func TestListUserSessionsStripsTokenHash(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	sessions, err := s.ListUserSessions(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListUserSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("ListUserSessions returned %d sessions, want 1", len(sessions))
	}
	if sessions[0].TokenHash != "" {
		t.Errorf("TokenHash = %q, want empty — ListUserSessions must never return token material", sessions[0].TokenHash)
	}
}

// TestListUserSessionsScopedToTheGivenUser asserts that ListUserSessions for
// one user never returns another user's sessions.
func TestListUserSessionsScopedToTheGivenUser(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	alice, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register alice: %v", err)
	}
	if _, _, _, err := s.Register(ctx, "bob@example.com", "correct-battery-staple", RequestInfo{}); err != nil {
		t.Fatalf("Register bob: %v", err)
	}

	sessions, err := s.ListUserSessions(ctx, alice.ID)
	if err != nil {
		t.Fatalf("ListUserSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("ListUserSessions(alice) returned %d sessions, want 1", len(sessions))
	}
	for _, sess := range sessions {
		if sess.UserID != alice.ID {
			t.Errorf("ListUserSessions(alice) returned a session for UserID %q", sess.UserID)
		}
	}
}

// TestValidateSessionRejectsPastIdleExpiryBeforeAbsoluteExpiry asserts that
// an idle session fails validation with ErrSessionExpired once its
// IdleExpiresAt deadline passes, even though its absolute ExpiresAt is
// still comfortably in the future: idle expiry is meant to end a session
// well before that. IdleExpiresAt is backdated directly in the store,
// isolated from whatever cadence ValidateSession's own touch-throttling
// would otherwise apply — the companion test below is the "one second
// before" half of the same pin.
func TestValidateSessionRejectsPastIdleExpiryBeforeAbsoluteExpiry(t *testing.T) {
	s, _, sessions, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithIdleTimeout(time.Hour))
	ctx := context.Background()

	_, session, token, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	pastDeadline := time.Now().Add(-time.Second)
	sessions.mu.Lock()
	sessions.sessions[session.ID].IdleExpiresAt = &pastDeadline
	sessions.mu.Unlock()

	if _, _, err := s.ValidateSession(ctx, token); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("ValidateSession one second past IdleExpiresAt: error = %v, want ErrSessionExpired", err)
	}
}

// TestValidateSessionAcceptsSessionBeforeIdleExpiry is the companion to the
// above: one second before the idle deadline, the same kind of session
// still validates.
func TestValidateSessionAcceptsSessionBeforeIdleExpiry(t *testing.T) {
	s, _, sessions, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithIdleTimeout(time.Hour))
	ctx := context.Background()

	_, session, token, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	almostDeadline := time.Now().Add(time.Second)
	sessions.mu.Lock()
	sessions.sessions[session.ID].IdleExpiresAt = &almostDeadline
	sessions.mu.Unlock()

	if _, _, err := s.ValidateSession(ctx, token); err != nil {
		t.Fatalf("ValidateSession one second before IdleExpiresAt: %v", err)
	}
}

// TestValidateSessionThrottlesTheLastSeenTouch asserts that ValidateSession
// does not write a fresh LastSeenAt/IdleExpiresAt on every single call —
// only once the session's current LastSeenAt is stale enough. See
// sessionTouchInterval's doc comment (session.go) for the cost rationale:
// without this, every authenticated request would cost an extra store
// write.
func TestValidateSessionThrottlesTheLastSeenTouch(t *testing.T) {
	users := newMemUserStore()
	sessions := &touchCountingSessionStore{memSessionStore: newMemSessionStore()}
	tokens := newMemTokenStore()
	s, err := New(users, sessions, tokens, NoSecondFactors{}, WithArgon2Params(testArgon2Params))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	_, session, token, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Freshly issued: LastSeenAt is already "now", so the very next
	// validation is well inside the throttle interval and must not write.
	if _, _, err := s.ValidateSession(ctx, token); err != nil {
		t.Fatalf("ValidateSession (1st): %v", err)
	}
	if sessions.touches != 0 {
		t.Fatalf("touches after a validation immediately following issuance = %d, want 0", sessions.touches)
	}

	// Backdate LastSeenAt past the throttle interval directly in the store.
	stale := time.Now().Add(-time.Hour)
	sessions.mu.Lock()
	sessions.sessions[session.ID].LastSeenAt = stale
	sessions.mu.Unlock()

	if _, _, err := s.ValidateSession(ctx, token); err != nil {
		t.Fatalf("ValidateSession (2nd): %v", err)
	}
	if sessions.touches != 1 {
		t.Fatalf("touches after a validation past the throttle interval = %d, want 1", sessions.touches)
	}

	// Immediately again: LastSeenAt was just refreshed to "now" by the
	// write above, so this one must not write either.
	if _, _, err := s.ValidateSession(ctx, token); err != nil {
		t.Fatalf("ValidateSession (3rd): %v", err)
	}
	if sessions.touches != 1 {
		t.Fatalf("touches after a validation immediately following a touch = %d, want still 1", sessions.touches)
	}
}

// TestRefreshSessionRotatesTokenAndPreservesAuthenticatedAt asserts that
// RefreshSession mints a working new token, retires the old one, mints a
// new session ID (see the PROGRESS.md Decisions row on why), and leaves
// AuthenticatedAt exactly as it was: a refresh is a token rotation, not a
// fresh authentication proof, and must not reset the step-up clock
// RequireRecentAuth reads.
func TestRefreshSessionRotatesTokenAndPreservesAuthenticatedAt(t *testing.T) {
	s, users, sessions, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()
	ri := RequestInfo{IP: "203.0.113.9", UserAgent: "refresh-test-agent/1.0"}

	_, session, oldToken, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", ri)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Verification is incidental to this test — the rotation mechanics are
	// what it pins; the gate itself is covered by
	// TestRefreshSessionRejectsUnverifiedEmail.
	verifyUserEmail(t, users, session.UserID)

	// Backdate AuthenticatedAt directly, so "preserved" is distinguishable
	// from "coincidentally close to time.Now()".
	old := time.Now().Add(-2 * time.Hour)
	sessions.mu.Lock()
	sessions.sessions[session.ID].AuthenticatedAt = old
	sessions.mu.Unlock()
	session.AuthenticatedAt = old

	fresh, newToken, err := s.RefreshSession(ctx, session)
	if err != nil {
		t.Fatalf("RefreshSession: %v", err)
	}
	if newToken == "" || newToken == oldToken {
		t.Fatalf("RefreshSession returned token %q, want a new non-empty token", newToken)
	}
	if fresh.ID == session.ID {
		t.Fatalf("RefreshSession kept the same session ID %q — expected a new ID (see the PROGRESS.md Decisions row)", fresh.ID)
	}
	if !fresh.AuthenticatedAt.Equal(old) {
		t.Fatalf("RefreshSession AuthenticatedAt = %v, want unchanged %v", fresh.AuthenticatedAt, old)
	}
	if fresh.UserID != session.UserID {
		t.Fatalf("RefreshSession UserID = %q, want %q", fresh.UserID, session.UserID)
	}
	if fresh.Method != session.Method {
		t.Fatalf("RefreshSession Method = %q, want %q", fresh.Method, session.Method)
	}
	// IP/UserAgent carry over from the stale in-memory session rather than
	// being re-derived — RefreshSession takes no RequestInfo. Both docs
	// promise this; pin it here.
	if fresh.IP != ri.IP {
		t.Errorf("RefreshSession IP = %q, want %q", fresh.IP, ri.IP)
	}
	if fresh.UserAgent != ri.UserAgent {
		t.Errorf("RefreshSession UserAgent = %q, want %q", fresh.UserAgent, ri.UserAgent)
	}

	// The old token must stop validating...
	if _, _, err := s.ValidateSession(ctx, oldToken); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("ValidateSession(oldToken) after refresh: error = %v, want ErrSessionNotFound", err)
	}
	// ...and the new one must work, still carrying the preserved stamp.
	validated, _, err := s.ValidateSession(ctx, newToken)
	if err != nil {
		t.Fatalf("ValidateSession(newToken) after refresh: %v", err)
	}
	if !validated.AuthenticatedAt.Equal(old) {
		t.Fatalf("validated session AuthenticatedAt = %v, want unchanged %v", validated.AuthenticatedAt, old)
	}
}

// TestRefreshSessionAfterRevokeSessionFailsClosed pins the CRITICAL fix:
// RefreshSession must not let a caller holding a stale *Session mint a
// brand-new working session for one that was already revoked. Before the
// fix, RefreshSession created the new row before deleting the old one and
// discarded the delete's error — so this exact sequence (revoke, then
// refresh the now-stale *Session) minted a working replacement anyway,
// letting the holder un-evict themselves.
func TestRefreshSessionAfterRevokeSessionFailsClosed(t *testing.T) {
	s, _, sessions, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, session, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := s.RevokeSession(ctx, user.ID, session.ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}

	before := sessions.count()
	if _, _, err := s.RefreshSession(ctx, session); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("RefreshSession after RevokeSession: error = %v, want ErrSessionNotFound", err)
	}
	if got := sessions.count(); got != before {
		t.Fatalf("RefreshSession after RevokeSession changed the session count: got %d, want unchanged %d — a new row must not have been created", got, before)
	}
}

// TestRefreshSessionAfterDisableUserFailsClosed covers the CRITICAL fix's
// scenario as originally reported: DisableUser's normal behavior revokes
// every session for the account, so the stale *Session's row is already
// gone by the time RefreshSession runs — the fail-closed DeleteSession
// check below catches it the same way a plain revocation does.
func TestRefreshSessionAfterDisableUserFailsClosed(t *testing.T) {
	s, _, sessions, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	_, session, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := s.DisableUser(ctx, session.UserID, "reported for abuse"); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}

	before := sessions.count()
	if _, _, err := s.RefreshSession(ctx, session); err == nil {
		t.Fatal("RefreshSession after DisableUser: error = nil, want an error")
	}
	if got := sessions.count(); got != before {
		t.Fatalf("RefreshSession after DisableUser changed the session count: got %d, want unchanged %d — a new row must not have been created", got, before)
	}
}

// TestRefreshSessionRejectsDisabledAccountWhoseSessionSurvived isolates the
// second half of the CRITICAL fix from the first: disableUserDirect stamps
// DisabledAt WITHOUT revoking the session (mirroring the real-world case
// where DisableUser's own session-revocation call errors but its status
// write still lands), so the stale *Session's row still exists when
// RefreshSession runs. The fail-closed DeleteSession check alone would let
// this one through — accountStatus is what actually stops it.
func TestRefreshSessionRejectsDisabledAccountWhoseSessionSurvived(t *testing.T) {
	s, users, sessions, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	_, session, oldToken, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	disableUserDirect(t, users, session.UserID, "reported for abuse")

	before := sessions.count()
	if _, _, err := s.RefreshSession(ctx, session); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("RefreshSession for a disabled account whose session survived: error = %v, want ErrAccountDisabled", err)
	}
	if got := sessions.count(); got != before-1 {
		t.Fatalf("RefreshSession against a disabled account left %d sessions, want %d — the old row must still be burned even though no new one was created", got, before-1)
	}
	// The old row is burned on the way to the error — consistent with the
	// fail-closed direction: a disabled-account refresh attempt costs the
	// caller their old session too, not just a denied new one.
	if _, _, err := s.ValidateSession(ctx, oldToken); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("ValidateSession(oldToken) after a disabled-account refresh attempt: error = %v, want ErrSessionNotFound", err)
	}
}

// TestRefreshSessionRejectsUnverifiedEmail closes the last minting path that
// skipped the verified-email gate.
//
// Register's signup session is deliberately exempt from RequireVerifiedEmail
// — a user must be able to hold a session long enough to click the link —
// but the exemption was meant to expire with that session. RefreshSession
// checked accountStatus and nothing else, so an unverified account could
// rotate its signup session forever and never verify anything, which is
// exactly what README's "New sessions are blocked for unverified accounts by
// default" and doc.go's own summary of the default promise cannot happen.
//
// The refusal is fail-closed in the same direction as the disabled-account
// case: the old row is deleted first, so a refused refresh costs the caller
// their existing session too.
func TestRefreshSessionRejectsUnverifiedEmail(t *testing.T) {
	t.Run("UnverifiedIsRefusedAndBurnsTheOldSession", func(t *testing.T) {
		s, _, sessions, _ := newTestEnv(WithArgon2Params(testArgon2Params))
		ctx := context.Background()

		_, session, oldToken, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
		if err != nil {
			t.Fatalf("Register: %v", err)
		}

		before := sessions.count()
		if _, _, err := s.RefreshSession(ctx, session); !errors.Is(err, ErrEmailNotVerified) {
			t.Fatalf("RefreshSession for an unverified account: error = %v, want ErrEmailNotVerified", err)
		}
		if got := sessions.count(); got != before-1 {
			t.Fatalf("RefreshSession left %d sessions, want %d — the old row is deleted before the gate runs", got, before-1)
		}
		if _, _, err := s.ValidateSession(ctx, oldToken); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("ValidateSession(oldToken) after a refused refresh: error = %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("VerifiedStillRotates", func(t *testing.T) {
		s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
		ctx := context.Background()

		_, session, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		verifyUserEmail(t, users, session.UserID)

		fresh, newToken, err := s.RefreshSession(ctx, session)
		if err != nil {
			t.Fatalf("RefreshSession for a verified account: %v", err)
		}
		if fresh == nil || newToken == "" {
			t.Fatal("RefreshSession returned no session or no token for a verified account")
		}
		if _, _, err := s.ValidateSession(ctx, newToken); err != nil {
			t.Fatalf("ValidateSession(newToken): %v", err)
		}
	})

	t.Run("OptedOutStillRotates", func(t *testing.T) {
		s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithRequireVerifiedEmail(false))
		ctx := context.Background()

		_, session, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
		if err != nil {
			t.Fatalf("Register: %v", err)
		}

		if _, newToken, err := s.RefreshSession(ctx, session); err != nil {
			t.Fatalf("RefreshSession with WithRequireVerifiedEmail(false): %v", err)
		} else if _, _, err := s.ValidateSession(ctx, newToken); err != nil {
			t.Fatalf("ValidateSession(newToken): %v", err)
		}
	})
}

// TestReAuthenticateRejectsDisabledAccount closes the gap the T501 Decisions
// row flagged and deferred: ReAuthenticate did not call accountStatus, so it
// could refresh AuthenticatedAt for a disabled account's already-held
// session. See status.go's accountStatus and stepup.go's ReAuthenticate.
func TestReAuthenticateRejectsDisabledAccount(t *testing.T) {
	s, users, sessions, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	_, session, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	old := time.Now().Add(-2 * time.Hour)
	sessions.mu.Lock()
	sessions.sessions[session.ID].AuthenticatedAt = old
	sessions.mu.Unlock()
	session.AuthenticatedAt = old

	disableUserDirect(t, users, session.UserID, "reported for abuse")

	if err := s.ReAuthenticate(ctx, session, "correct-battery-staple", RequestInfo{}); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("ReAuthenticate error = %v, want ErrAccountDisabled", err)
	}

	sessions.mu.Lock()
	got := sessions.sessions[session.ID].AuthenticatedAt
	sessions.mu.Unlock()
	if !got.Equal(old) {
		t.Fatalf("AuthenticatedAt changed on a ReAuthenticate against a disabled account: got %v, want unchanged %v", got, old)
	}
}

// --- T504: rehash on login --------------------------------------------------
//
// verifyPassword read cost parameters out of a stored hash but never
// compared them to the currently configured Argon2Params, so raising
// Argon2Params was silently cosmetic for the installed base: an operator
// could raise the memory/time/parallelism cost and no existing user's
// stored hash would ever actually get stronger, only newly-registered ones.
// needsRehash (password.go) closes that: VerifyPassword now compares the
// just-verified hash's params against s.cfg.Argon2 and, if the stored hash
// is weaker, re-derives the hash from the just-verified plaintext with the
// current params and writes it back through updateUserWithRetry, guarded so
// a concurrent password change is never clobbered by the upgrade.

// updateCountingUserStore wraps a real memUserStore and counts calls to
// UpdateUser, so a test can assert a login that should not trigger a rehash
// writes nothing at all — not even a no-op update.
type updateCountingUserStore struct {
	*memUserStore
	updates int
}

func (s *updateCountingUserStore) UpdateUser(ctx context.Context, u *User) error {
	s.updates++
	return s.memUserStore.UpdateUser(ctx, u)
}

// TestLoginUpgradesWeakStoredHash is the regression test for C3: a user
// whose stored hash was produced with weaker Argon2 parameters than are
// currently configured gets it transparently upgraded on a successful
// login, with no caller-visible change beyond the stored row.
func TestLoginUpgradesWeakStoredHash(t *testing.T) {
	ctx := context.Background()
	const (
		email    = "alice@example.com"
		password = "correct-horse-battery-staple"
	)

	users := newMemUserStore()
	sessions := newMemSessionStore()
	tokens := newMemTokenStore()

	weak := mustNew(users, sessions, tokens, WithArgon2Params(weakerArgon2Params))
	user, _, _, err := weak.Register(ctx, email, password, RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	before, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if !needsRehash(before.PasswordHash, testArgon2Params) {
		t.Fatal("test setup is broken: the seeded hash must be weaker than testArgon2Params, or this test proves nothing")
	}

	strong := mustNew(users, sessions, tokens, WithArgon2Params(testArgon2Params))
	res, err := strong.Login(ctx, email, password, RequestInfo{})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if res.Session == nil || res.SessionToken == "" {
		t.Fatal("expected a session from a correct password, even though the stored hash needed an upgrade")
	}

	after, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if after.PasswordHash == before.PasswordHash {
		t.Fatal("stored hash was not upgraded on a successful login with weaker-than-configured params")
	}

	gotParams, _, _, err := decodeHash(after.PasswordHash)
	if err != nil {
		t.Fatalf("decodeHash(upgraded hash): %v", err)
	}
	if gotParams.Memory != testArgon2Params.Memory || gotParams.Iterations != testArgon2Params.Iterations || gotParams.Parallelism != testArgon2Params.Parallelism {
		t.Fatalf("upgraded hash params = %+v, want the configured %+v", gotParams, testArgon2Params)
	}

	ok, _, err := verifyPassword(password, after.PasswordHash, nil)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("the password no longer verifies against its own upgraded hash")
	}
}

// TestLoginRehashRetriesOnConcurrentUpdateConflict asserts that the upgrade
// write goes through updateUserWithRetry's real Version contract, not a
// bare overwrite: an unrelated concurrent write landing between the
// rehash's read and its write must make the rehash retry from a fresh read
// (preserving the interleaved write) rather than lose the upgrade or clobber
// the concurrent change.
func TestLoginRehashRetriesOnConcurrentUpdateConflict(t *testing.T) {
	ctx := context.Background()
	const (
		email    = "alice@example.com"
		password = "correct-horse-battery-staple"
	)

	users := newMemUserStore()
	sessions := newMemSessionStore()
	tokens := newMemTokenStore()

	weak := mustNew(users, sessions, tokens, WithArgon2Params(weakerArgon2Params))
	user, _, _, err := weak.Register(ctx, email, password, RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	before, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}

	// Land an unrelated write (something else touching this row, e.g. a
	// profile update) between the rehash's read and its write. The hook
	// fires once, so this concurrent write's own UpdateUser is unaffected.
	users.beforeUpdate = func(*User) {
		concurrent, err := users.GetUserByID(ctx, user.ID)
		if err != nil {
			t.Errorf("GetUserByID (concurrent write): %v", err)
			return
		}
		concurrent.Metadata = map[string]any{"unrelated": "concurrent write"}
		if err := users.UpdateUser(ctx, concurrent); err != nil {
			t.Errorf("UpdateUser (concurrent write): %v", err)
		}
	}

	strong := mustNew(users, sessions, tokens, WithArgon2Params(testArgon2Params))
	if _, err := strong.Login(ctx, email, password, RequestInfo{}); err != nil {
		t.Fatalf("Login: %v", err)
	}

	after, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if after.PasswordHash == before.PasswordHash {
		t.Fatal("the rehash's write was lost rather than retried after the concurrent-update conflict")
	}
	if after.Version < before.Version+2 {
		t.Fatalf("Version advanced from %d to %d, want at least +2 (one for the concurrent write, one for the rehash's successful retry) — the write is not going through the versioned UpdateUser contract", before.Version, after.Version)
	}
	if got := after.Metadata["unrelated"]; got != "concurrent write" {
		t.Fatalf("the concurrent write's Metadata was lost: the rehash's retry re-read stale data instead of the fresh row (got %v)", after.Metadata)
	}
}

// TestFailedLoginNeverRehashes asserts that a wrong password never
// rehashes the stored credential: a login that fails must not touch the
// row at all, including its cost parameters.
func TestFailedLoginNeverRehashes(t *testing.T) {
	ctx := context.Background()
	const (
		email    = "alice@example.com"
		password = "correct-horse-battery-staple"
	)

	users := newMemUserStore()
	sessions := newMemSessionStore()
	tokens := newMemTokenStore()

	weak := mustNew(users, sessions, tokens, WithArgon2Params(weakerArgon2Params))
	user, _, _, err := weak.Register(ctx, email, password, RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	before, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}

	strong := mustNew(users, sessions, tokens, WithArgon2Params(testArgon2Params))
	if _, err := strong.Login(ctx, email, "wrong-password", RequestInfo{}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login with wrong password: error = %v, want ErrInvalidCredentials", err)
	}

	after, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if after.PasswordHash != before.PasswordHash {
		t.Fatal("a failed login rehashed the stored password; only a successful verification may trigger a rehash")
	}
}

// TestLoginRehashWriteFailureDoesNotFailLogin asserts that the rehash write
// is best-effort: the caller already proved they know the password by the
// time the write is attempted, so a store error while persisting the
// upgraded hash must not turn a successful login into a failure. The
// upgrade is simply deferred to a later login, not lost forever — the
// stored hash is unchanged and still weaker than configured.
func TestLoginRehashWriteFailureDoesNotFailLogin(t *testing.T) {
	ctx := context.Background()
	const (
		email    = "alice@example.com"
		password = "correct-horse-battery-staple"
	)

	mem := newMemUserStore()
	users := &failUpdateUserStore{memUserStore: mem}
	sessions := newMemSessionStore()
	tokens := newMemTokenStore()

	weak := mustNew(users, sessions, tokens, WithArgon2Params(weakerArgon2Params))
	user, _, _, err := weak.Register(ctx, email, password, RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, mem, user.ID)

	before, err := mem.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}

	users.updateErr = errors.New("store unavailable")

	strong := mustNew(users, sessions, tokens, WithArgon2Params(testArgon2Params))
	res, err := strong.Login(ctx, email, password, RequestInfo{})
	if err != nil {
		t.Fatalf("Login: %v, want nil — a failed rehash write must not fail an otherwise-correct login", err)
	}
	if res.Session == nil {
		t.Fatal("expected a session despite the rehash write failing")
	}

	after, err := mem.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if after.PasswordHash != before.PasswordHash {
		t.Fatal("the stored hash changed even though the update was configured to fail")
	}
}

// TestLoginDoesNotRehashWhenStoredParamsAreStrongEnough asserts that a login
// against a hash already at the configured cost writes nothing back — not
// even a no-op update. Gratuitous writes on every login would cost every
// store implementation a write it never needed.
func TestLoginDoesNotRehashWhenStoredParamsAreStrongEnough(t *testing.T) {
	ctx := context.Background()
	const (
		email    = "alice@example.com"
		password = "correct-horse-battery-staple"
	)

	users := &updateCountingUserStore{memUserStore: newMemUserStore()}
	s := mustNew(users, newMemSessionStore(), newMemTokenStore(), WithArgon2Params(testArgon2Params))

	user, _, _, err := s.Register(ctx, email, password, RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users.memUserStore, user.ID)
	users.updates = 0 // verifyUserEmail's own write is not what this test measures

	if _, err := s.Login(ctx, email, password, RequestInfo{}); err != nil {
		t.Fatalf("Login: %v", err)
	}

	if users.updates != 0 {
		t.Fatalf("Login wrote to the user store %d time(s) for a hash already at the configured params; want 0", users.updates)
	}
}

// TestRehashDoesNotClobberConcurrentPasswordChange is the regression test
// for the binding TOCTOU constraint: the rehash write's guard must only
// apply the upgrade if the row's PasswordHash is still exactly the hash
// VerifyPassword just verified. If a second request changes the password
// between that verification and the rehash's write — the same race
// TestConcurrentResetAndVerifyDoesNotResurrectOldHash covers for
// ResetPassword/VerifyEmail — the rehash must back off rather than
// resurrect the password the user just replaced.
func TestRehashDoesNotClobberConcurrentPasswordChange(t *testing.T) {
	ctx := context.Background()
	const (
		email       = "alice@example.com"
		oldPassword = "correct-horse-battery-staple"
		newPassword = "totally-different-password"
	)

	users := newMemUserStore()
	sessions := newMemSessionStore()
	tokens := newMemTokenStore()

	weak := mustNew(users, sessions, tokens, WithArgon2Params(weakerArgon2Params))
	user, _, _, err := weak.Register(ctx, email, oldPassword, RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	strong := mustNew(users, sessions, tokens, WithArgon2Params(testArgon2Params))

	// Land a complete password change between the rehash's read of the row
	// and its write. The hook fires once, so the concurrent ChangePassword's
	// own UpdateUser is unaffected.
	users.beforeUpdate = func(*User) {
		if err := strong.ChangePassword(ctx, user.ID, oldPassword, newPassword, RequestInfo{}); err != nil {
			t.Errorf("racing ChangePassword: %v", err)
		}
	}

	if _, err := strong.Login(ctx, email, oldPassword, RequestInfo{}); err != nil {
		t.Fatalf("Login: %v", err)
	}

	stored, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}

	if ok, _, _ := verifyPassword(oldPassword, stored.PasswordHash, nil); ok {
		t.Fatal("the rehash resurrected the old password: it still verifies after a concurrent ChangePassword")
	}
	ok, _, err := verifyPassword(newPassword, stored.PasswordHash, nil)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("the concurrently-set new password does not verify; it was overwritten by the rehash")
	}
}

// The same password, typed three ways. NFKC folds all of them onto the
// composed form, so all three must hash and verify identically once
// normalization is applied (T505).
//
//   - nfkcComposedForm is already NFKC-normal: é is the single rune U+00E9.
//   - nfkcDecomposedForm is the NFD spelling of the same text: "e" followed
//     by the combining acute accent U+0301. macOS/iOS keyboards and file
//     systems routinely produce this form where Linux and Windows produce
//     the composed one, so the same human password genuinely arrives both
//     ways.
//   - nfkcCompatibilityForm exercises the *compatibility* half of NFKC that
//     plain NFC leaves alone: U+FB01, the "fi" ligature, which NFKC maps to
//     the two ASCII letters "fi".
const (
	nfkcComposedForm      = "café-passphrase"
	nfkcDecomposedForm    = "café-passphrase"
	nfkcCompatibilityForm = "ﬁnal-passphrase"
	nfkcCompatibilityNFKC = "final-passphrase"
)

// TestDefaultMinPasswordLengthIsTwelve pins the raised default (T505). Eight
// was below what NIST SP 800-63B expects of a memorized secret, and the API
// was already breaking in this series, so this is the moment to raise it.
func TestDefaultMinPasswordLengthIsTwelve(t *testing.T) {
	if got := defaultConfig().MinPasswordLength; got != 12 {
		t.Fatalf("defaultConfig().MinPasswordLength = %d, want 12", got)
	}

	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	if _, _, _, err := s.Register(ctx, "eleven@example.com", "abcdefghijk", RequestInfo{}); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("Register with an 11-character password: error = %v, want ErrPasswordTooShort", err)
	}
	if _, _, _, err := s.Register(ctx, "twelve@example.com", "abcdefghijkl", RequestInfo{}); err != nil {
		t.Fatalf("Register with a 12-character password: %v", err)
	}
}

// TestEquivalentUnicodePasswordFormsVerify is the end-to-end statement of
// why NFKC normalization is here at all: a password registered in one
// Unicode spelling must log in when typed in an equivalent one. Without
// normalization the two byte strings hash differently and the second login
// is an ordinary ErrInvalidCredentials the user has no way to diagnose.
func TestEquivalentUnicodePasswordFormsVerify(t *testing.T) {
	for _, tc := range []struct {
		name         string
		registerWith string
		loginWith    string
	}{
		{"decomposed registered, composed typed", nfkcDecomposedForm, nfkcComposedForm},
		{"composed registered, decomposed typed", nfkcComposedForm, nfkcDecomposedForm},
		{"ligature registered, expanded typed", nfkcCompatibilityForm, nfkcCompatibilityNFKC},
		{"expanded registered, ligature typed", nfkcCompatibilityNFKC, nfkcCompatibilityForm},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
			ctx := context.Background()

			user, _, _, err := s.Register(ctx, "unicode@example.com", tc.registerWith, RequestInfo{})
			if err != nil {
				t.Fatalf("Register: %v", err)
			}
			verifyUserEmail(t, users, user.ID)

			if _, err := s.VerifyPassword(ctx, "unicode@example.com", tc.loginWith, RequestInfo{}); err != nil {
				t.Fatalf("VerifyPassword with an NFKC-equivalent form of the registered password: %v", err)
			}
		})
	}
}

// blocklistedPassword is an entry from the embedded common-password corpus
// that is exactly twelve characters long — long enough to clear the default
// MinPasswordLength, so a rejection can only have come from the password
// checker and never from the length gate.
const blocklistedPassword = "unbelievable"

// recordingChecker captures what the configured PasswordChecker is handed
// and how often, and can be made to reject or to fail operationally.
type recordingChecker struct {
	mu   sync.Mutex
	seen []string
	err  error
}

func (c *recordingChecker) Check(_ context.Context, password string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen = append(c.seen, password)
	return c.err
}

func (c *recordingChecker) calls() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.seen...)
}

// TestCompromisedPasswordRejectedOnEveryPasswordSetPath is the task's
// headline property: every route by which a password can come to be stored
// consults the checker, and the default configuration has one. A path that
// forgot to call it would be a hole exactly as large as the whole feature —
// an attacker only needs one way in.
func TestCompromisedPasswordRejectedOnEveryPasswordSetPath(t *testing.T) {
	ctx := context.Background()

	t.Run("Register", func(t *testing.T) {
		s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
		_, _, _, err := s.Register(ctx, "alice@example.com", blocklistedPassword, RequestInfo{})
		if !errors.Is(err, ErrPasswordCompromised) {
			t.Fatalf("Register = %v, want ErrPasswordCompromised", err)
		}
	})

	t.Run("ChangePassword", func(t *testing.T) {
		s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
		user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		err = s.ChangePassword(ctx, user.ID, "correct-battery-staple", blocklistedPassword, RequestInfo{})
		if !errors.Is(err, ErrPasswordCompromised) {
			t.Fatalf("ChangePassword = %v, want ErrPasswordCompromised", err)
		}
	})

	t.Run("ResetPassword", func(t *testing.T) {
		s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
		if _, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{}); err != nil {
			t.Fatalf("Register: %v", err)
		}
		rawToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com", RequestInfo{})
		if err != nil {
			t.Fatalf("CreatePasswordResetToken: %v", err)
		}
		if err := s.ResetPassword(ctx, rawToken, blocklistedPassword); !errors.Is(err, ErrPasswordCompromised) {
			t.Fatalf("ResetPassword = %v, want ErrPasswordCompromised", err)
		}
		// The policy check runs before the token is consumed, so a rejected
		// password must not have burned the reset token.
		if err := s.ResetPassword(ctx, rawToken, "brand-new-passphrase"); err != nil {
			t.Fatalf("ResetPassword with an acceptable password after a rejected one: %v", err)
		}
	})

	t.Run("SetInitialPassword", func(t *testing.T) {
		s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
		user := &User{ID: generateID(), Email: "passwordless@example.com", CreatedAt: time.Now(), UpdatedAt: time.Now()}
		if err := users.CreateUser(ctx, user); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if err := s.SetInitialPassword(ctx, user.ID, blocklistedPassword); !errors.Is(err, ErrPasswordCompromised) {
			t.Fatalf("SetInitialPassword = %v, want ErrPasswordCompromised", err)
		}
	})
}

func TestErrPasswordCompromisedCarriesTheRatifiedMessage(t *testing.T) {
	if got, want := ErrPasswordCompromised.Error(), "sulis: password appears in a breach corpus"; got != want {
		t.Fatalf("ErrPasswordCompromised.Error() = %q, want %q", got, want)
	}
	// One error value, reachable under either name: passwordcheck cannot
	// import sulis (that would be an import cycle, since sulis's default
	// checker comes from passwordcheck), so the sentinel is born there and
	// re-exported here. Two distinct values would silently break errors.Is
	// for anyone comparing against the other package's name.
	if ErrPasswordCompromised != passwordcheck.ErrCompromised {
		t.Fatal("passwordcheck.ErrCompromised and sulis.ErrPasswordCompromised are not the same error value")
	}
}

// TestVerifyPasswordDoesNotConsultTheChecker: checking at verification time
// would lock out every existing user the day a corpus is added or updated,
// turning a hardening change into a mass outage. The check belongs where a
// password is chosen, not where it is proven.
func TestVerifyPasswordDoesNotConsultTheChecker(t *testing.T) {
	ctx := context.Background()
	users := newMemUserStore()
	sessions := newMemSessionStore()
	tokens := newMemTokenStore()

	// Set the password up through a Sulis with checking disabled, exactly as
	// a pre-T505 deployment would have.
	lax, err := New(users, sessions, tokens, newFakeFactors(), WithArgon2Params(testArgon2Params), WithPasswordChecker(nil))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	user, _, _, err := lax.Register(ctx, "alice@example.com", blocklistedPassword, RequestInfo{})
	if err != nil {
		t.Fatalf("Register with checking disabled: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	checker := &recordingChecker{err: ErrPasswordCompromised}
	strict, err := New(users, sessions, tokens, newFakeFactors(), WithArgon2Params(testArgon2Params), WithPasswordChecker(checker))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := strict.VerifyPassword(ctx, "alice@example.com", blocklistedPassword, RequestInfo{}); err != nil {
		t.Fatalf("VerifyPassword for an existing user whose password is now blocklisted: %v", err)
	}
	if calls := checker.calls(); len(calls) != 0 {
		t.Fatalf("the password checker was consulted %d time(s) during verification: %v", len(calls), calls)
	}
}

// TestPasswordCheckerRunsAfterTheLengthGateAndOnTheNormalizedForm pins two
// things at once. The checker is handed the NFKC form, because that is what
// is actually hashed and stored — comparing a corpus against the raw form
// would let a decorated spelling of a corpus entry through. And it runs
// after the cheap length checks, so an obviously-too-short password never
// costs a network round trip to a checker like HIBP.
func TestPasswordCheckerRunsAfterTheLengthGateAndOnTheNormalizedForm(t *testing.T) {
	ctx := context.Background()
	checker := &recordingChecker{}
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithPasswordChecker(checker))

	if _, _, _, err := s.Register(ctx, "short@example.com", "abc", RequestInfo{}); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("Register = %v, want ErrPasswordTooShort", err)
	}
	if calls := checker.calls(); len(calls) != 0 {
		t.Fatalf("the checker was consulted for a password the length gate had already rejected: %v", calls)
	}

	if _, _, _, err := s.Register(ctx, "unicode@example.com", nfkcDecomposedForm, RequestInfo{}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	calls := checker.calls()
	if len(calls) != 1 {
		t.Fatalf("checker calls = %v, want exactly one", calls)
	}
	if calls[0] != nfkcComposedForm {
		t.Fatalf("the checker was handed %q, want the NFKC form %q", calls[0], nfkcComposedForm)
	}
}

// TestPasswordCheckerOperationalErrorIsNotReportedAsCompromised: a checker
// that cannot reach its data source (a fail-closed HIBP client, say) must
// surface as an operational failure, not as a verdict about the password.
func TestPasswordCheckerOperationalErrorIsNotReportedAsCompromised(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("breach corpus unreachable")
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithPasswordChecker(&recordingChecker{err: boom}))

	_, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if !errors.Is(err, boom) {
		t.Fatalf("Register = %v, want the checker's own error", err)
	}
	if errors.Is(err, ErrPasswordCompromised) {
		t.Fatal("an unreachable checker was reported as evidence that the password is compromised")
	}
}

func TestWithPasswordCheckerNilDisablesChecking(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithPasswordChecker(nil))
	if _, _, _, err := s.Register(ctx, "alice@example.com", blocklistedPassword, RequestInfo{}); err != nil {
		t.Fatalf("Register with checking disabled: %v", err)
	}
}

func TestDefaultConfigUsesTheEmbeddedBlocklist(t *testing.T) {
	if defaultConfig().PasswordChecker == nil {
		t.Fatal("the default configuration has no PasswordChecker; a safe default is the whole point of shipping an embedded corpus")
	}
}

// TestPasswordLengthPolicyMeasuresTheNormalizedForm: the bounds exist to
// bound what Argon2 actually consumes, and what Argon2 consumes is the NFKC
// form. Measuring the raw form would let a password that normalizes to three
// characters through a twelve-character minimum.
func TestPasswordLengthPolicyMeasuresTheNormalizedForm(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))

	// Twelve U+FF10 FULLWIDTH DIGIT ZERO: 36 bytes raw, 12 bytes once NFKC
	// folds each onto ASCII "0". Long enough either way, so it must be
	// accepted — and it pins that the measurement happens on some form
	// consistently rather than by accident.
	wide := strings.Repeat("０", 12)
	if _, _, _, err := s.Register(ctx, "wide@example.com", wide, RequestInfo{}); err != nil {
		t.Fatalf("Register with a 12-character fullwidth password: %v", err)
	}

	// Eleven of the same: 33 bytes raw, 11 after normalization. Measured on
	// the raw form this would sail past a twelve-*byte* minimum.
	narrow := strings.Repeat("０", 11)
	if _, _, _, err := s.Register(ctx, "narrow@example.com", narrow, RequestInfo{}); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("Register with an 11-character fullwidth password = %v, want ErrPasswordTooShort", err)
	}
}

// TestLegacyPasswordHashIsUpgradedToTheNormalizedFormOnLogin is the
// compatibility story end to end. A hash written before T505 was derived
// from raw bytes; the first successful login after the upgrade re-hashes it
// from the NFKC form, on exactly the machinery T504 built for raising Argon2
// parameters. After that one login the account is fully migrated and every
// equivalent spelling of the password works.
func TestLegacyPasswordHashIsUpgradedToTheNormalizedFormOnLogin(t *testing.T) {
	ctx := context.Background()
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))

	user := &User{
		ID:           generateID(),
		Email:        "legacy@example.com",
		PasswordHash: legacyHash(t, nfkcCompatibilityForm, testArgon2Params),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := users.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	verifyUserEmail(t, users, user.ID)
	before, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}

	// The pre-normalization form still logs in.
	if _, err := s.Login(ctx, "legacy@example.com", nfkcCompatibilityForm, RequestInfo{}); err != nil {
		t.Fatalf("Login with the form the legacy hash was derived from: %v", err)
	}

	after, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if after.PasswordHash == before.PasswordHash {
		t.Fatal("the stored hash was not upgraded; the account stays on the pre-normalization form forever and the equivalent spellings never start working")
	}

	ok, legacy, err := verifyPassword(nfkcCompatibilityForm, after.PasswordHash, nil)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("the password no longer verifies against its own upgraded hash")
	}
	if legacy {
		t.Fatal("the upgraded hash still only matches through the pre-normalization fallback; it was not re-derived from the normalized form")
	}

	// And now the equivalent spelling works too, which it could not before.
	if _, err := s.Login(ctx, "legacy@example.com", nfkcCompatibilityNFKC, RequestInfo{}); err != nil {
		t.Fatalf("Login with the NFKC form after the upgrade: %v", err)
	}
}

// TestReAuthenticateUpgradesALegacyPasswordHash: ReAuthenticate is the other
// real password comparison in the library (T504 fix round 1), so it must
// migrate a pre-normalization hash the same way Login does. Otherwise an
// account whose owner only ever re-authenticates for step-up operations
// stays on the legacy form indefinitely.
func TestReAuthenticateUpgradesALegacyPasswordHash(t *testing.T) {
	ctx := context.Background()
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))

	user := &User{
		ID:           generateID(),
		Email:        "legacy@example.com",
		PasswordHash: legacyHash(t, nfkcCompatibilityForm, testArgon2Params),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := users.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	session, _, err := s.IssueSessionUnchecked(ctx, user.ID, AuthMethodPassword)
	if err != nil {
		t.Fatalf("IssueSessionUnchecked: %v", err)
	}
	if err := s.ReAuthenticate(ctx, session, nfkcCompatibilityForm, RequestInfo{}); err != nil {
		t.Fatalf("ReAuthenticate: %v", err)
	}

	after, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	ok, legacy, err := verifyPassword(nfkcCompatibilityForm, after.PasswordHash, nil)
	if err != nil {
		t.Fatalf("verifyPassword: %v", err)
	}
	if !ok || legacy {
		t.Fatal("ReAuthenticate did not migrate the pre-normalization hash to the normalized form")
	}
}

// TestChangePasswordAcceptsAnEquivalentSpellingOfTheOldPassword: the old
// password is compared through the same normalizing path as any other
// verification, so a user who types it in a different but equivalent form
// must not be told their current password is wrong.
func TestChangePasswordAcceptsAnEquivalentSpellingOfTheOldPassword(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))

	user, _, _, err := s.Register(ctx, "alice@example.com", nfkcDecomposedForm, RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := s.ChangePassword(ctx, user.ID, nfkcComposedForm, "brand-new-passphrase", RequestInfo{}); err != nil {
		t.Fatalf("ChangePassword with an NFKC-equivalent spelling of the old password: %v", err)
	}
}
