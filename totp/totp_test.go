package totp

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// mustService creates a Service, failing the test if construction errors.
func mustService(t *testing.T, store Store, issuer string, opts ...Option) *Service {
	t.Helper()
	svc, err := NewService(store, issuer, opts...)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

// errTOTPCounterRegressed is returned by memTOTPStore.SaveTOTP when a save
// would lower LastUsedCounter for an existing credential with the same ID,
// per the fail-closed contract documented on Store.SaveTOTP.
var errTOTPCounterRegressed = errors.New("totp: counter would regress for existing credential")

// In-memory TOTP store for testing. active and pending are separate maps,
// mirroring the Store contract's separation of an active (verified)
// credential from a pending (unverified) enrollment: see EnrollPending and
// ConfirmEnrollment for where the atomicity that separation depends on is
// documented and enforced.
type memTOTPStore struct {
	mu      sync.Mutex
	active  map[string]*Credential
	pending map[string]*Credential
}

func newMemTOTPStore() *memTOTPStore {
	return &memTOTPStore{
		active:  make(map[string]*Credential),
		pending: make(map[string]*Credential),
	}
}

func (s *memTOTPStore) GetActiveTOTP(_ context.Context, userID string) (*Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.active[userID]
	if !ok {
		return nil, ErrTOTPNotEnrolled
	}
	cp := *c
	return &cp, nil
}

func (s *memTOTPStore) GetPendingTOTP(_ context.Context, userID string) (*Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.pending[userID]
	if !ok {
		return nil, ErrTOTPNotEnrolled
	}
	cp := *c
	return &cp, nil
}

// EnrollPending implements the atomic guard documented on
// Store.EnrollPending: the active-credential check and the pending write
// both happen while holding s.mu, so a concurrent ConfirmEnrollment cannot
// promote a different pending enrollment to active in the gap between the
// check and the write (see
// TestConfirmEnrollmentIsAtomicUnderConcurrentEnrollPending).
func (s *memTOTPStore) EnrollPending(_ context.Context, cred *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.active[cred.UserID]; ok {
		return ErrTOTPAlreadyEnrolled
	}
	cp := *cred
	s.pending[cred.UserID] = &cp
	return nil
}

func (s *memTOTPStore) ReplacePending(_ context.Context, cred *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *cred
	s.pending[cred.UserID] = &cp
	return nil
}

// ConfirmEnrollment implements the atomic promotion documented on
// Store.ConfirmEnrollment: the pendingID comparison and the promotion
// (removing the pending enrollment, installing it as active) both happen
// while holding s.mu, so a concurrent EnrollPending/ReplacePending call
// cannot land between them undetected.
func (s *memTOTPStore) ConfirmEnrollment(_ context.Context, userID, pendingID string, counter uint64) (*Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[userID]
	if !ok || p.ID != pendingID {
		return nil, ErrTOTPNotEnrolled
	}
	// Carry the replay-protection counter forward monotonically: a
	// factor swap must never roll it backward, even though the promoted
	// credential has a different secret than whatever was active before.
	if active, ok := s.active[userID]; ok && active.LastUsedCounter > counter {
		counter = active.LastUsedCounter
	}
	promoted := &Credential{
		ID:              p.ID,
		UserID:          userID,
		Secret:          p.Secret,
		Verified:        true,
		LastUsedCounter: counter,
		CreatedAt:       p.CreatedAt,
	}
	s.active[userID] = promoted
	delete(s.pending, userID)
	cp := *promoted
	return &cp, nil
}

func (s *memTOTPStore) SaveTOTP(_ context.Context, cred *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.active[cred.UserID]; ok {
		if existing.ID == cred.ID && cred.LastUsedCounter < existing.LastUsedCounter {
			return errTOTPCounterRegressed
		}
	}
	cp := *cred
	s.active[cred.UserID] = &cp
	return nil
}

func (s *memTOTPStore) DeleteTOTP(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.active, userID)
	delete(s.pending, userID)
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

// failOnNthSaveStore wraps memTOTPStore and fails the Nth call (1-indexed) to
// SaveTOTP, used to exercise fail-closed behavior when persisting fails.
type failOnNthSaveStore struct {
	*memTOTPStore
	failOn int
	calls  int
}

func (s *failOnNthSaveStore) SaveTOTP(ctx context.Context, cred *Credential) error {
	s.calls++
	if s.calls == s.failOn {
		return errors.New("simulated save failure")
	}
	return s.memTOTPStore.SaveTOTP(ctx, cred)
}

func TestGenerateCodeRFC6238(t *testing.T) {
	// RFC 6238 Appendix B test vectors for SHA1.
	// Secret: "12345678901234567890" (ASCII) = base32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	cfg := Config{
		Algorithm: AlgorithmSHA1,
		Digits:    8,
		Period:    30,
	}

	tests := []struct {
		time     int64
		expected string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			got, err := generateCode(secret, time.Unix(tc.time, 0), cfg)
			if err != nil {
				t.Fatalf("generateCode: %v", err)
			}
			if got != tc.expected {
				t.Fatalf("time=%d: expected %s, got %s", tc.time, tc.expected, got)
			}
		})
	}
}

func TestGenerateCode6Digits(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	cfg := Config{
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Period:    30,
	}

	code, err := generateCode(secret, time.Unix(59, 0), cfg)
	if err != nil {
		t.Fatalf("generateCode: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", code)
	}
}

func TestEnrollAndValidate(t *testing.T) {
	store := newMemTOTPStore()
	svc := mustService(t, store, "TestApp")
	ctx := context.Background()

	secret, uri, err := svc.Enroll(ctx, "user1", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if secret == "" {
		t.Fatal("expected non-empty secret")
	}
	if uri == "" {
		t.Fatal("expected non-empty URI")
	}

	// Generate a valid code and confirm enrollment.
	code, err := svc.Generate(secret, time.Now())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if err := svc.ConfirmEnrollment(ctx, "user1", code); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}

	// Validate should now work. Confirmation already consumed the counter
	// for `code`, so use a code from the next window to avoid a replay
	// rejection.
	period := time.Duration(svc.cfg.Period) * time.Second
	code, _ = svc.Generate(secret, time.Now().Add(period))
	if err := svc.Validate(ctx, "user1", code); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Wrong code should fail with ErrTOTPInvalid.
	if err := svc.Validate(ctx, "user1", "000000"); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("expected ErrTOTPInvalid, got %v", err)
	}
}

func TestValidateBeforeConfirm(t *testing.T) {
	store := newMemTOTPStore()
	svc := mustService(t, store, "TestApp")
	ctx := context.Background()

	secret, _, _ := svc.Enroll(ctx, "user1", "alice@example.com")
	code, _ := svc.Generate(secret, time.Now())

	err := svc.Validate(ctx, "user1", code)
	if err != ErrTOTPNotVerified {
		t.Fatalf("expected ErrTOTPNotVerified, got %v", err)
	}
}

func TestUnenroll(t *testing.T) {
	store := newMemTOTPStore()
	svc := mustService(t, store, "TestApp")
	ctx := context.Background()

	svc.Enroll(ctx, "user1", "alice@example.com")
	svc.Unenroll(ctx, "user1")

	err := svc.Validate(ctx, "user1", "123456")
	if err != ErrTOTPNotEnrolled {
		t.Fatalf("expected ErrTOTPNotEnrolled, got %v", err)
	}
}

// TestValidateRejectsWrongCodeWithError proves the bypass described in the
// task brief is unwritable: an incorrect code must return a non-nil error
// distinguishable as ErrTOTPInvalid via errors.Is, not (false, nil). Calling
// code that only checks `err != nil` before granting access must reject a
// wrong code, not silently let it through.
func TestValidateRejectsWrongCodeWithError(t *testing.T) {
	store := newMemTOTPStore()
	svc := mustService(t, store, "TestApp")
	ctx := context.Background()

	secret, _, err := svc.Enroll(ctx, "user1", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	code, err := svc.Generate(secret, time.Now())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.ConfirmEnrollment(ctx, "user1", code); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}

	err = svc.Validate(ctx, "user1", "000000")
	if err == nil {
		t.Fatal("Validate returned a nil error for a wrong code")
	}
	if !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("expected ErrTOTPInvalid, got %v", err)
	}
}

func TestValidateRejectsReplayedCode(t *testing.T) {
	store := newMemTOTPStore()
	svc := mustService(t, store, "TestApp")
	ctx := context.Background()

	secret, _, err := svc.Enroll(ctx, "user1", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	code, err := svc.Generate(secret, time.Now())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.ConfirmEnrollment(ctx, "user1", code); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}

	// ConfirmEnrollment already consumed this counter, so the same code
	// must not be replayable as a login code.
	err = svc.Validate(ctx, "user1", code)
	if !errors.Is(err, ErrTOTPReplayed) {
		t.Fatalf("expected ErrTOTPReplayed, got %v", err)
	}
}

func TestValidateAcceptsNextWindowCode(t *testing.T) {
	store := newMemTOTPStore()
	svc := mustService(t, store, "TestApp")
	ctx := context.Background()

	secret, _, err := svc.Enroll(ctx, "user1", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	now := time.Now()
	codeT, err := svc.Generate(secret, now)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.ConfirmEnrollment(ctx, "user1", codeT); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}

	period := time.Duration(svc.cfg.Period) * time.Second
	codeNext, err := svc.Generate(secret, now.Add(period))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if err := svc.Validate(ctx, "user1", codeNext); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateRejectsOlderWindowAfterNewer(t *testing.T) {
	store := newMemTOTPStore()
	svc := mustService(t, store, "TestApp")
	ctx := context.Background()

	secret, _, err := svc.Enroll(ctx, "user1", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	now := time.Now()
	codeT, err := svc.Generate(secret, now)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.ConfirmEnrollment(ctx, "user1", codeT); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}

	period := time.Duration(svc.cfg.Period) * time.Second
	codeNext, err := svc.Generate(secret, now.Add(period))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.Validate(ctx, "user1", codeNext); err != nil {
		t.Fatalf("Validate(next) = %v, want nil", err)
	}

	// Once the newer window's code has been used, the older code's
	// counter is superseded and must be rejected as a replay.
	err = svc.Validate(ctx, "user1", codeT)
	if !errors.Is(err, ErrTOTPReplayed) {
		t.Fatalf("expected ErrTOTPReplayed, got %v", err)
	}
}

func TestValidatePersistsLastUsedCounter(t *testing.T) {
	store := newMemTOTPStore()
	svc := mustService(t, store, "TestApp")
	ctx := context.Background()

	secret, _, err := svc.Enroll(ctx, "user1", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	now := time.Now()
	codeT, err := svc.Generate(secret, now)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.ConfirmEnrollment(ctx, "user1", codeT); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}

	period := time.Duration(svc.cfg.Period) * time.Second
	next := now.Add(period)
	codeNext, err := svc.Generate(secret, next)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.Validate(ctx, "user1", codeNext); err != nil {
		t.Fatalf("Validate(next) = %v, want nil", err)
	}

	wantCounter := uint64(next.Unix()) / svc.cfg.Period
	cred, err := store.GetActiveTOTP(ctx, "user1")
	if err != nil {
		t.Fatalf("GetActiveTOTP: %v", err)
	}
	if cred.LastUsedCounter != wantCounter {
		t.Fatalf("LastUsedCounter = %d, want %d", cred.LastUsedCounter, wantCounter)
	}
}

func TestValidateFailsClosedWhenPersistFails(t *testing.T) {
	base := newMemTOTPStore()
	// Enroll now goes through EnrollPending and ConfirmEnrollment through
	// Store.ConfirmEnrollment — neither calls SaveTOTP any more. Validate's
	// post-check counter persist is the only SaveTOTP call in this
	// scenario, so failing the 1st (and only) call exercises the
	// fail-closed path.
	store := &failOnNthSaveStore{memTOTPStore: base, failOn: 1}
	svc := mustService(t, store, "TestApp")
	ctx := context.Background()

	secret, _, err := svc.Enroll(ctx, "user1", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	now := time.Now()
	codeT, err := svc.Generate(secret, now)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.ConfirmEnrollment(ctx, "user1", codeT); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}

	period := time.Duration(svc.cfg.Period) * time.Second
	codeNext, err := svc.Generate(secret, now.Add(period))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	err = svc.Validate(ctx, "user1", codeNext)
	if err == nil {
		t.Fatal("expected an error when persisting LastUsedCounter fails")
	}
}

// TestConfirmEnrollmentCarriesCounterForwardAcrossReplace pins the monotonic
// property documented on Store.ConfirmEnrollment: promoting a pending
// enrollment created via ReplaceEnrollment never sets LastUsedCounter lower
// than what the factor it replaces had already recorded, even though the
// new credential has an entirely different secret. Without this, replacing
// a factor would reset a user's replay-protection clock to whatever the
// confirmation code's own time window happens to be — usually harmless in
// practice, but not a property the store contract should leave unpinned.
//
// This supersedes the old (pre-T302) TestConfirmEnrollmentDoesNotRollBackCounter,
// which exercised re-confirming the *same* pending enrollment twice — no
// longer possible now that ConfirmEnrollment consumes the pending slot
// exactly once (see the Store.ConfirmEnrollment GoDoc); the equivalent
// concern under the active/pending split is a factor *replacement*, not a
// re-confirmation, which is what this test exercises instead.
func TestConfirmEnrollmentCarriesCounterForwardAcrossReplace(t *testing.T) {
	store := newMemTOTPStore()
	svc := mustService(t, store, "TestApp")
	ctx := context.Background()

	secret, _, err := svc.Enroll(ctx, "user1", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	code, err := svc.Generate(secret, time.Now())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.ConfirmEnrollment(ctx, "user1", code); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}

	// Artificially inflate the active credential's recorded counter far
	// beyond what any freshly-generated confirmation code could naturally
	// match, so the assertion below depends on promotion's carry-forward
	// logic, not coincidence.
	activeBefore, err := store.GetActiveTOTP(ctx, "user1")
	if err != nil {
		t.Fatalf("GetActiveTOTP: %v", err)
	}
	inflatedCounter := activeBefore.LastUsedCounter + 1_000_000
	activeBefore.LastUsedCounter = inflatedCounter
	if err := store.SaveTOTP(ctx, activeBefore); err != nil {
		t.Fatalf("SaveTOTP (inflate counter): %v", err)
	}

	newSecret, _, err := svc.ReplaceEnrollment(ctx, "user1", "alice@example.com")
	if err != nil {
		t.Fatalf("ReplaceEnrollment: %v", err)
	}
	newCode, err := svc.Generate(newSecret, time.Now())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.ConfirmEnrollment(ctx, "user1", newCode); err != nil {
		t.Fatalf("ConfirmEnrollment (replacement): %v", err)
	}

	promoted, err := store.GetActiveTOTP(ctx, "user1")
	if err != nil {
		t.Fatalf("GetActiveTOTP (after replacement): %v", err)
	}
	if promoted.Secret != newSecret {
		t.Fatalf("active secret = %q, want the replacement secret %q", promoted.Secret, newSecret)
	}
	if promoted.LastUsedCounter < inflatedCounter {
		t.Fatalf("LastUsedCounter = %d, want >= %d (carried forward from the replaced factor)", promoted.LastUsedCounter, inflatedCounter)
	}
}

// TestMemTOTPStoreRejectsLoweredCounterForSameCredential asserts that the
// reference in-memory store enforces the fail-closed monotonicity contract
// documented on Store.SaveTOTP: a save for an existing ACTIVE credential ID
// must not be allowed to lower LastUsedCounter, since that would let a
// concurrent, already-superseded validate win a replay race. A save under a
// different credential ID for the same user is unaffected and always
// succeeds, even with a lower or zero counter — SaveTOTP only guards
// against regressing the counter of the credential currently active, by
// ID; installing a different one as active (a direct store write, not part
// of the Enroll/ConfirmEnrollment flow, which now goes through
// EnrollPending/ConfirmEnrollment instead) is unguarded.
func TestMemTOTPStoreRejectsLoweredCounterForSameCredential(t *testing.T) {
	store := newMemTOTPStore()
	ctx := context.Background()

	cred := &Credential{ID: "cred-1", UserID: "user1", Secret: "SECRET", Verified: true, LastUsedCounter: 10}
	if err := store.SaveTOTP(ctx, cred); err != nil {
		t.Fatalf("SaveTOTP (initial): %v", err)
	}

	// Same credential ID, lower counter: must be rejected.
	lowered := &Credential{ID: "cred-1", UserID: "user1", Secret: "SECRET", Verified: true, LastUsedCounter: 5}
	if err := store.SaveTOTP(ctx, lowered); !errors.Is(err, errTOTPCounterRegressed) {
		t.Fatalf("expected errTOTPCounterRegressed, got %v", err)
	}
	// The rejected save must not have overwritten the stored counter.
	got, err := store.GetActiveTOTP(ctx, "user1")
	if err != nil {
		t.Fatalf("GetActiveTOTP: %v", err)
	}
	if got.LastUsedCounter != 10 {
		t.Fatalf("expected stored counter to remain 10, got %d", got.LastUsedCounter)
	}

	// Same credential ID, equal counter: must succeed (ConfirmEnrollment's
	// no-op-counter re-save relies on this).
	same := &Credential{ID: "cred-1", UserID: "user1", Secret: "SECRET", Verified: true, LastUsedCounter: 10}
	if err := store.SaveTOTP(ctx, same); err != nil {
		t.Fatalf("SaveTOTP (equal counter): %v", err)
	}

	// Different credential ID for the same user: always succeeds, even with
	// a lower/zero counter.
	reenrolled := &Credential{ID: "cred-2", UserID: "user1", Secret: "OTHERSECRET", Verified: false, LastUsedCounter: 0}
	if err := store.SaveTOTP(ctx, reenrolled); err != nil {
		t.Fatalf("SaveTOTP (different ID): %v", err)
	}
}

func TestNewServiceRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		opts []Option
	}{
		{"digits too low", []Option{WithDigits(5)}},
		{"digits too high", []Option{WithDigits(9)}},
		{"period zero", []Option{WithPeriod(0)}},
		{"period too high", []Option{WithPeriod(301)}},
		{"skew too high", []Option{WithSkew(5)}},
		{"secret size too small", []Option{WithSecretSize(15)}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemTOTPStore()
			_, err := NewService(store, "TestApp", tc.opts...)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}

	t.Run("empty issuer", func(t *testing.T) {
		store := newMemTOTPStore()
		_, err := NewService(store, "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("issuer containing colon", func(t *testing.T) {
		store := newMemTOTPStore()
		_, err := NewService(store, "My:App")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestNewServiceAcceptsDefaults(t *testing.T) {
	store := newMemTOTPStore()
	svc, err := NewService(store, "TestApp")
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestOTPAuthURI(t *testing.T) {
	uri := buildOTPAuthURI("MyApp", "alice@example.com", "JBSWY3DPEHPK3PXP", Config{
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Period:    30,
	})
	if uri == "" {
		t.Fatal("expected non-empty URI")
	}
	// Should start with otpauth://totp/
	if uri[:15] != "otpauth://totp/" {
		t.Fatalf("unexpected URI prefix: %s", uri)
	}
}

// TestValidateConsultsLimiterBeforeCheckingCode asserts that Validate
// consults the configured limiter as its first action, keyed by
// "totp:"+userID, and never evaluates the code when the limiter denies —
// proven here by denying for a userID with no enrollment at all: a store
// lookup or code check would fail differently (ErrTOTPNotEnrolled), not with
// ErrTOTPRateLimited.
func TestValidateConsultsLimiterBeforeCheckingCode(t *testing.T) {
	store := newMemTOTPStore()
	limiter := &fakeLimiter{denied: true}
	svc := mustService(t, store, "TestApp", WithLimiter(limiter))
	ctx := context.Background()

	err := svc.Validate(ctx, "user1", "000000")
	if !errors.Is(err, ErrTOTPRateLimited) {
		t.Fatalf("expected ErrTOTPRateLimited, got %v", err)
	}
	if len(limiter.keys) != 1 || limiter.keys[0] != "totp:user1" {
		t.Fatalf("expected limiter to be consulted with key %q, got %v", "totp:user1", limiter.keys)
	}
}

// TestConfirmEnrollmentConsultsLimiterBeforeCheckingCode mirrors
// TestValidateConsultsLimiterBeforeCheckingCode for ConfirmEnrollment.
func TestConfirmEnrollmentConsultsLimiterBeforeCheckingCode(t *testing.T) {
	store := newMemTOTPStore()
	limiter := &fakeLimiter{denied: true}
	svc := mustService(t, store, "TestApp", WithLimiter(limiter))
	ctx := context.Background()

	err := svc.ConfirmEnrollment(ctx, "user1", "000000")
	if !errors.Is(err, ErrTOTPRateLimited) {
		t.Fatalf("expected ErrTOTPRateLimited, got %v", err)
	}
	if len(limiter.keys) != 1 || limiter.keys[0] != "totp:user1" {
		t.Fatalf("expected limiter to be consulted with key %q, got %v", "totp:user1", limiter.keys)
	}
}

// TestTOTPNilLimiterIsNoOp asserts that omitting WithLimiter (the default)
// never blocks Validate or ConfirmEnrollment.
func TestTOTPNilLimiterIsNoOp(t *testing.T) {
	store := newMemTOTPStore()
	svc := mustService(t, store, "TestApp")
	ctx := context.Background()

	secret, _, err := svc.Enroll(ctx, "user1", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	code, err := svc.Generate(secret, time.Now())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.ConfirmEnrollment(ctx, "user1", code); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}

	period := time.Duration(svc.cfg.Period) * time.Second
	codeNext, err := svc.Generate(secret, time.Now().Add(period))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.Validate(ctx, "user1", codeNext); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// TestEnrollReturnsErrTOTPAlreadyEnrolledForVerifiedUser is the regression
// test for the bypass described in the T302 task brief: a stray Enroll call
// (a double-submitted form, a CSRF'd POST, a retried request) must not be
// able to overwrite a user's active, verified TOTP factor. Enroll now
// refuses outright once a verified enrollment exists; ReplaceEnrollment is
// the explicit path for superseding one on purpose (see
// TestReplaceEnrollmentSupersedesActiveEnrollmentExplicitly).
func TestEnrollReturnsErrTOTPAlreadyEnrolledForVerifiedUser(t *testing.T) {
	store := newMemTOTPStore()
	svc := mustService(t, store, "TestApp")
	ctx := context.Background()

	secret, _, err := svc.Enroll(ctx, "user1", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	code, err := svc.Generate(secret, time.Now())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.ConfirmEnrollment(ctx, "user1", code); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}

	_, _, err = svc.Enroll(ctx, "user1", "alice@example.com")
	if !errors.Is(err, ErrTOTPAlreadyEnrolled) {
		t.Fatalf("Enroll() error = %v, want ErrTOTPAlreadyEnrolled", err)
	}

	// The clobber this guards against: the active credential must be
	// completely untouched by the refused Enroll call.
	active, err := store.GetActiveTOTP(ctx, "user1")
	if err != nil {
		t.Fatalf("GetActiveTOTP: %v", err)
	}
	if active.Secret != secret {
		t.Fatalf("active secret changed after a refused Enroll: got %q, want the original %q", active.Secret, secret)
	}

	// The original factor must still validate.
	period := time.Duration(svc.cfg.Period) * time.Second
	nextCode, err := svc.Generate(secret, time.Now().Add(period))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.Validate(ctx, "user1", nextCode); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// TestPendingEnrollmentDoesNotDisturbActiveCredential asserts that starting
// a replacement enrollment (which creates a pending, unverified credential
// alongside the existing active one) has no effect on Validate: the active
// credential keeps working, using its own secret, for as long as the
// pending enrollment sits unconfirmed.
func TestPendingEnrollmentDoesNotDisturbActiveCredential(t *testing.T) {
	store := newMemTOTPStore()
	svc := mustService(t, store, "TestApp")
	ctx := context.Background()

	secret, _, err := svc.Enroll(ctx, "user1", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	code, err := svc.Generate(secret, time.Now())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.ConfirmEnrollment(ctx, "user1", code); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}

	// Start (but do not confirm) a replacement enrollment.
	newSecret, _, err := svc.ReplaceEnrollment(ctx, "user1", "alice@example.com")
	if err != nil {
		t.Fatalf("ReplaceEnrollment: %v", err)
	}
	if newSecret == secret {
		t.Fatal("ReplaceEnrollment returned the same secret as the active credential")
	}

	// The active credential must still validate codes for the ORIGINAL
	// secret while the pending one sits unconfirmed.
	period := time.Duration(svc.cfg.Period) * time.Second
	nextCode, err := svc.Generate(secret, time.Now().Add(period))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.Validate(ctx, "user1", nextCode); err != nil {
		t.Fatalf("Validate against the active secret failed while a pending enrollment exists: %v", err)
	}

	// A code for the still-unconfirmed pending secret must not validate —
	// it isn't active yet.
	pendingCode, err := svc.Generate(newSecret, time.Now())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.Validate(ctx, "user1", pendingCode); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("Validate accepted a code for the unconfirmed pending secret: err = %v, want ErrTOTPInvalid", err)
	}
}

// TestReplaceEnrollmentSupersedesActiveEnrollmentExplicitly asserts
// ReplaceEnrollment's contrast with Enroll: it succeeds despite an active,
// verified factor already existing (returning a new secret/URI), the old
// factor stays active — and Validate keeps accepting codes for it — until
// the replacement is confirmed, at which point the replacement becomes
// active and the original secret stops working.
func TestReplaceEnrollmentSupersedesActiveEnrollmentExplicitly(t *testing.T) {
	store := newMemTOTPStore()
	svc := mustService(t, store, "TestApp")
	ctx := context.Background()

	oldSecret, _, err := svc.Enroll(ctx, "user1", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	oldCode, err := svc.Generate(oldSecret, time.Now())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.ConfirmEnrollment(ctx, "user1", oldCode); err != nil {
		t.Fatalf("ConfirmEnrollment: %v", err)
	}

	newSecret, newURI, err := svc.ReplaceEnrollment(ctx, "user1", "alice@example.com")
	if err != nil {
		t.Fatalf("ReplaceEnrollment() error = %v, want nil (must supersede despite an active factor)", err)
	}
	if newSecret == "" || newURI == "" {
		t.Fatal("ReplaceEnrollment returned an empty secret or URI")
	}
	if newSecret == oldSecret {
		t.Fatal("ReplaceEnrollment returned the same secret as the active credential")
	}

	// Old factor stays active until the new one is confirmed.
	period := time.Duration(svc.cfg.Period) * time.Second
	oldNextCode, err := svc.Generate(oldSecret, time.Now().Add(period))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.Validate(ctx, "user1", oldNextCode); err != nil {
		t.Fatalf("Validate(old secret) before confirmation = %v, want nil", err)
	}

	newCode, err := svc.Generate(newSecret, time.Now())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.ConfirmEnrollment(ctx, "user1", newCode); err != nil {
		t.Fatalf("ConfirmEnrollment (replacement): %v", err)
	}

	// The replacement is now active …
	active, err := store.GetActiveTOTP(ctx, "user1")
	if err != nil {
		t.Fatalf("GetActiveTOTP: %v", err)
	}
	if active.Secret != newSecret {
		t.Fatalf("active secret = %q, want the replacement secret %q", active.Secret, newSecret)
	}

	// … and the original secret's codes no longer validate.
	oldFurtherCode, err := svc.Generate(oldSecret, time.Now().Add(2*period))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.Validate(ctx, "user1", oldFurtherCode); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("Validate accepted the superseded factor's code: err = %v, want ErrTOTPInvalid", err)
	}
}

// TestConfirmEnrollmentIsAtomicUnderConcurrentEnrollPending is the
// regression test for the concurrency half of the T302 task brief: a
// concurrent Enroll and ConfirmEnrollment race must not let a pending
// enrollment clobber a factor verified in between (or, symmetrically, let a
// promotion silently discard a fresh enrollment attempt racing it). It
// exercises Store.EnrollPending and Store.ConfirmEnrollment directly,
// mirroring TestMemTOTPStoreRejectsLoweredCounterForSameCredential's
// whitebox approach, since Service.ConfirmEnrollment itself does a
// non-atomic read (GetPendingTOTP, to validate a code against the pending
// secret) before calling the store's atomic promotion — the atomicity
// contract lives in the store, on the pendingID compare-and-swap, exactly
// where Store.ConfirmEnrollment's GoDoc documents it.
//
// Modeled on T201's TestFinishDiscoverableLoginConsumesChallengeExactlyOnce
// and T205's TestDeleteCredentialGuardIsAtomicUnderConcurrentDeletes: both
// goroutines are released from a shared start gate on every iteration, and
// the property is checked across many iterations since a single run can
// get lucky.
//
// The two racers are:
//   - ConfirmEnrollment(userID, "pending-1", ...): promotes the pending
//     enrollment set up before the race, if it's still current.
//   - EnrollPending(cred-2): a racing (e.g. double-submitted) Enroll call,
//     which supersedes the pending enrollment if no active credential
//     exists yet.
//
// Given the store's single mutex serializes both critical sections into a
// strict total order, exactly one of the two must win on every iteration:
// either the confirm's compare-and-swap runs first (pending-1 gets
// promoted, and the racing EnrollPending then sees an active credential
// and is refused with ErrTOTPAlreadyEnrolled), or EnrollPending runs first
// (superseding the pending enrollment with cred-2, so the confirm's
// compare-and-swap finds pending-1 gone and returns ErrTOTPNotEnrolled).
// Both succeeding would mean the guard let a torn state through; both
// failing would mean the guard incorrectly locked out a legitimate winner.
func TestConfirmEnrollmentIsAtomicUnderConcurrentEnrollPending(t *testing.T) {
	const iterations = 200

	for i := 0; i < iterations; i++ {
		store := newMemTOTPStore()
		ctx := context.Background()

		pending := &Credential{ID: "pending-1", UserID: "user1", Secret: "SECRET1", CreatedAt: time.Now()}
		if err := store.EnrollPending(ctx, pending); err != nil {
			t.Fatalf("iteration %d: EnrollPending (setup): %v", i, err)
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		var confirmed *Credential
		var confirmErr, enrollErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			confirmed, confirmErr = store.ConfirmEnrollment(ctx, "user1", "pending-1", 42)
		}()
		go func() {
			defer wg.Done()
			<-start
			enrollErr = store.EnrollPending(ctx, &Credential{ID: "pending-2", UserID: "user1", Secret: "SECRET2", CreatedAt: time.Now()})
		}()
		close(start)
		wg.Wait()

		confirmOK := confirmErr == nil
		enrollOK := enrollErr == nil
		if confirmOK == enrollOK {
			t.Fatalf("iteration %d: confirmErr=%v enrollErr=%v — want exactly one to succeed", i, confirmErr, enrollErr)
		}

		active, activeErr := store.GetActiveTOTP(ctx, "user1")
		if confirmOK {
			if !errors.Is(enrollErr, ErrTOTPAlreadyEnrolled) {
				t.Fatalf("iteration %d: confirm won but Enroll's error = %v, want ErrTOTPAlreadyEnrolled", i, enrollErr)
			}
			if activeErr != nil {
				t.Fatalf("iteration %d: GetActiveTOTP: %v", i, activeErr)
			}
			if active.ID != "pending-1" || active.Secret != "SECRET1" || !active.Verified {
				t.Fatalf("iteration %d: expected pending-1 promoted to active, got %+v", i, active)
			}
			if confirmed == nil || confirmed.ID != "pending-1" {
				t.Fatalf("iteration %d: ConfirmEnrollment returned %+v, want the promoted pending-1 credential", i, confirmed)
			}
		} else {
			if !errors.Is(confirmErr, ErrTOTPNotEnrolled) {
				t.Fatalf("iteration %d: Enroll won but confirmErr = %v, want ErrTOTPNotEnrolled", i, confirmErr)
			}
			if activeErr == nil {
				t.Fatalf("iteration %d: expected no active credential yet, got %+v", i, active)
			}
			p, err := store.GetPendingTOTP(ctx, "user1")
			if err != nil {
				t.Fatalf("iteration %d: GetPendingTOTP: %v", i, err)
			}
			if p.ID != "pending-2" {
				t.Fatalf("iteration %d: expected pending-2 to remain pending, got %+v", i, p)
			}
		}
	}
}
