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

// In-memory TOTP store for testing.
type memTOTPStore struct {
	mu    sync.Mutex
	creds map[string]*Credential
}

func newMemTOTPStore() *memTOTPStore {
	return &memTOTPStore{creds: make(map[string]*Credential)}
}

func (s *memTOTPStore) SaveTOTP(_ context.Context, cred *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.creds[cred.UserID]; ok {
		if existing.ID == cred.ID && cred.LastUsedCounter < existing.LastUsedCounter {
			return errTOTPCounterRegressed
		}
	}
	cp := *cred
	s.creds[cred.UserID] = &cp
	return nil
}

func (s *memTOTPStore) GetTOTPByUserID(_ context.Context, userID string) (*Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.creds[userID]
	if !ok {
		return nil, ErrTOTPNotEnrolled
	}
	cp := *c
	return &cp, nil
}

func (s *memTOTPStore) DeleteTOTP(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.creds, userID)
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
	ok, err := svc.Validate(ctx, "user1", code)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !ok {
		t.Fatal("Validate returned false for valid code")
	}

	// Wrong code should fail.
	ok, err = svc.Validate(ctx, "user1", "000000")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if ok {
		t.Fatal("Validate returned true for wrong code")
	}
}

func TestValidateBeforeConfirm(t *testing.T) {
	store := newMemTOTPStore()
	svc := mustService(t, store, "TestApp")
	ctx := context.Background()

	secret, _, _ := svc.Enroll(ctx, "user1", "alice@example.com")
	code, _ := svc.Generate(secret, time.Now())

	_, err := svc.Validate(ctx, "user1", code)
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

	_, err := svc.Validate(ctx, "user1", "123456")
	if err != ErrTOTPNotEnrolled {
		t.Fatalf("expected ErrTOTPNotEnrolled, got %v", err)
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
	ok, err := svc.Validate(ctx, "user1", code)
	if ok {
		t.Fatal("Validate returned true for replayed code")
	}
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

	ok, err := svc.Validate(ctx, "user1", codeNext)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !ok {
		t.Fatal("Validate returned false for next-window code")
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
	ok, err := svc.Validate(ctx, "user1", codeNext)
	if err != nil || !ok {
		t.Fatalf("Validate(next) = (%v, %v), want (true, nil)", ok, err)
	}

	// Once the newer window's code has been used, the older code's
	// counter is superseded and must be rejected as a replay.
	ok, err = svc.Validate(ctx, "user1", codeT)
	if ok {
		t.Fatal("Validate returned true for superseded older code")
	}
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
	ok, err := svc.Validate(ctx, "user1", codeNext)
	if err != nil || !ok {
		t.Fatalf("Validate(next) = (%v, %v), want (true, nil)", ok, err)
	}

	wantCounter := uint64(next.Unix()) / svc.cfg.Period
	cred, err := store.GetTOTPByUserID(ctx, "user1")
	if err != nil {
		t.Fatalf("GetTOTPByUserID: %v", err)
	}
	if cred.LastUsedCounter != wantCounter {
		t.Fatalf("LastUsedCounter = %d, want %d", cred.LastUsedCounter, wantCounter)
	}
}

func TestValidateFailsClosedWhenPersistFails(t *testing.T) {
	base := newMemTOTPStore()
	// Calls: 1) Enroll's SaveTOTP, 2) ConfirmEnrollment's SaveTOTP,
	// 3) Validate's SaveTOTP persisting the new counter — fail that one.
	store := &failOnNthSaveStore{memTOTPStore: base, failOn: 3}
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

	ok, err := svc.Validate(ctx, "user1", codeNext)
	if ok {
		t.Fatal("Validate returned true despite a persist failure")
	}
	if err == nil {
		t.Fatal("expected an error when persisting LastUsedCounter fails")
	}
}

func TestConfirmEnrollmentDoesNotRollBackCounter(t *testing.T) {
	store := newMemTOTPStore()
	svc := mustService(t, store, "TestApp")
	ctx := context.Background()

	secret, _, err := svc.Enroll(ctx, "user1", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	now := time.Now()
	period := time.Duration(svc.cfg.Period) * time.Second

	codeT, err := svc.Generate(secret, now)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	codeNext, err := svc.Generate(secret, now.Add(period))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Confirm with the later (T+period) code first, establishing counter N+1.
	if err := svc.ConfirmEnrollment(ctx, "user1", codeNext); err != nil {
		t.Fatalf("ConfirmEnrollment(next): %v", err)
	}
	credAfterFirst, err := store.GetTOTPByUserID(ctx, "user1")
	if err != nil {
		t.Fatalf("GetTOTPByUserID: %v", err)
	}
	wantCounter := credAfterFirst.LastUsedCounter

	// Re-confirm with the older, still skew-valid T code (e.g. a setup-retry
	// endpoint calling ConfirmEnrollment again). This must not roll the
	// counter backward and re-open replay of codes between N and N+1.
	if err := svc.ConfirmEnrollment(ctx, "user1", codeT); err != nil {
		t.Fatalf("ConfirmEnrollment(older): %v", err)
	}
	cred, err := store.GetTOTPByUserID(ctx, "user1")
	if err != nil {
		t.Fatalf("GetTOTPByUserID: %v", err)
	}
	if cred.LastUsedCounter != wantCounter {
		t.Fatalf("LastUsedCounter = %d, want %d (rolled back)", cred.LastUsedCounter, wantCounter)
	}

	// The older code must still be rejected as a replay.
	ok, err := svc.Validate(ctx, "user1", codeT)
	if ok {
		t.Fatal("Validate returned true for a code superseded before re-confirmation")
	}
	if !errors.Is(err, ErrTOTPReplayed) {
		t.Fatalf("expected ErrTOTPReplayed, got %v", err)
	}
}

// TestMemTOTPStoreRejectsLoweredCounterForSameCredential asserts that the
// reference in-memory store enforces the fail-closed monotonicity contract
// documented on Store.SaveTOTP: a save for an existing credential ID must
// not be allowed to lower LastUsedCounter, since that would let a
// concurrent, already-superseded validate win a replay race. A save under a
// different (re-enrollment) credential ID is unaffected and always
// succeeds, even with a lower or zero counter.
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
	got, err := store.GetTOTPByUserID(ctx, "user1")
	if err != nil {
		t.Fatalf("GetTOTPByUserID: %v", err)
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

	// Different credential ID (re-enrollment): always succeeds, even with a
	// lower/zero counter.
	reenrolled := &Credential{ID: "cred-2", UserID: "user1", Secret: "OTHERSECRET", Verified: false, LastUsedCounter: 0}
	if err := store.SaveTOTP(ctx, reenrolled); err != nil {
		t.Fatalf("SaveTOTP (re-enrollment): %v", err)
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

	ok, err := svc.Validate(ctx, "user1", "000000")
	if ok {
		t.Fatal("Validate returned true despite a denying limiter")
	}
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
	ok, err := svc.Validate(ctx, "user1", codeNext)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !ok {
		t.Fatal("expected Validate to succeed with a nil limiter")
	}
}
