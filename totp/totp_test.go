package totp

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

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
	svc := NewService(store, "TestApp")
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
	svc := NewService(store, "TestApp")
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
	svc := NewService(store, "TestApp")
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
	svc := NewService(store, "TestApp")
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
	svc := NewService(store, "TestApp")
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
	svc := NewService(store, "TestApp")
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
	svc := NewService(store, "TestApp")
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
	svc := NewService(store, "TestApp")
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
	svc := NewService(store, "TestApp")
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
