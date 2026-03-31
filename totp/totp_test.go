package totp

import (
	"context"
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

	// Validate should now work.
	code, _ = svc.Generate(secret, time.Now())
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
