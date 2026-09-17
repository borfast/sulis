package recovery

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// In-memory recovery code store for testing.
//
// It mirrors memstore.RecoveryStore, the reference implementation the
// storetest conformance suite is run against. It is duplicated rather than
// imported because these tests are in package recovery and memstore imports
// recovery — an import cycle Go rejects outright. Keep the two in step.
type memStore struct {
	mu    sync.Mutex
	codes map[string]map[string]struct{}
}

func newMemStore() *memStore {
	return &memStore{codes: make(map[string]map[string]struct{})}
}

func (m *memStore) ReplaceCodes(_ context.Context, userID string, hashes []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	set := make(map[string]struct{}, len(hashes))
	for _, h := range hashes {
		set[h] = struct{}{}
	}
	m.codes[userID] = set
	return nil
}

func (m *memStore) ConsumeCode(_ context.Context, userID, hash string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	set, ok := m.codes[userID]
	if !ok {
		return 0, ErrCodeNotFound
	}
	if _, ok := set[hash]; !ok {
		return 0, ErrCodeNotFound
	}
	delete(set, hash)
	return len(set), nil
}

func (m *memStore) CountCodes(_ context.Context, userID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.codes[userID]), nil
}

func (m *memStore) DeleteCodes(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.codes, userID)
	return nil
}

var (
	codeFormatRe = regexp.MustCompile(`^[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}$`)
	hashFormatRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func TestGenerateReturnsFormattedCodesAndStoresOnlyHashes(t *testing.T) {
	store := newMemStore()
	svc := mustService(t, store)
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(codes) != defaultCount {
		t.Fatalf("expected %d codes, got %d", defaultCount, len(codes))
	}
	for _, code := range codes {
		if !codeFormatRe.MatchString(code) {
			t.Errorf("code %q does not match xxxx-xxxx-xxxx-xxxx format", code)
		}
	}

	store.mu.Lock()
	hashes := store.codes["user1"]
	store.mu.Unlock()
	if len(hashes) != defaultCount {
		t.Fatalf("expected %d stored hashes, got %d", defaultCount, len(hashes))
	}
	for h := range hashes {
		if !hashFormatRe.MatchString(h) {
			t.Errorf("hash %q is not a 64-char hex string", h)
		}
		for _, code := range codes {
			if h == code {
				t.Errorf("store contains raw code %q instead of a hash", code)
			}
		}
	}
}

func TestGenerateReplacesPreviousSet(t *testing.T) {
	store := newMemStore()
	svc := mustService(t, store)
	ctx := context.Background()

	oldCodes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate (first): %v", err)
	}
	newCodes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate (second): %v", err)
	}

	if _, err := svc.Consume(ctx, "user1", oldCodes[0]); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("Consume(old code): expected ErrCodeInvalid, got %v", err)
	}
	if _, err := svc.Consume(ctx, "user1", newCodes[0]); err != nil {
		t.Fatalf("Consume(new code): expected nil, got %v", err)
	}
}

func TestConsumeAcceptsSloppyInput(t *testing.T) {
	store := newMemStore()
	svc := mustService(t, store)
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sloppy := "  " + strings.ToUpper(strings.ReplaceAll(codes[0], "-", "")) + "  "

	if _, err := svc.Consume(ctx, "user1", sloppy); err != nil {
		t.Fatalf("Consume(sloppy): expected nil, got %v", err)
	}
}

// TestCanonicalIsIdempotentWithInteriorWhitespace is a regression test for a
// bug FuzzRecoveryCanonical (task T402) found within its first two seconds
// of fuzzing: canonical's old TrimSpace-then-strip-dashes implementation
// only stripped whitespace from the string's *ends*. A non-space whitespace
// rune (e.g. a tab) sitting between a leading dash and the rest of the code
// survived the first canonical() call — the dash hadn't been stripped yet,
// so the tab wasn't at an edge TrimSpace would touch — but became the new
// leading character once the dash was removed, so a *second* call trimmed it
// away. That made canonical non-idempotent: canonical("-\t0") == "\t0", but
// canonical(canonical("-\t0")) == "0". Two codes differing only in whether
// canonical happened to run on them once or twice would hash differently,
// which is exactly the property this test and FuzzRecoveryCanonical both
// pin so it can't regress silently.
func TestCanonicalIsIdempotentWithInteriorWhitespace(t *testing.T) {
	const input = "-\t0"
	once := canonical(input)
	twice := canonical(once)
	if once != twice {
		t.Fatalf("canonical not idempotent: canonical(%q) = %q, canonical(that) = %q", input, once, twice)
	}
	if once != "0" {
		t.Fatalf("canonical(%q) = %q, want %q", input, once, "0")
	}
}

func TestConsumeIsSingleUse(t *testing.T) {
	store := newMemStore()
	svc := mustService(t, store)
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := svc.Consume(ctx, "user1", codes[0]); err != nil {
		t.Fatalf("first Consume: expected nil, got %v", err)
	}
	if _, err := svc.Consume(ctx, "user1", codes[0]); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("second Consume: expected ErrCodeInvalid, got %v", err)
	}
}

func TestConcurrentConsumeSingleWinner(t *testing.T) {
	store := newMemStore()
	svc := mustService(t, store, WithCount(1))
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	code := codes[0]

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = svc.Consume(ctx, "user1", code)
		}(i)
	}
	wg.Wait()

	var nilCount, invalidCount int
	for _, err := range errs {
		switch {
		case err == nil:
			nilCount++
		case errors.Is(err, ErrCodeInvalid):
			invalidCount++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if nilCount != 1 || invalidCount != 1 {
		t.Fatalf("expected exactly one winner and one ErrCodeInvalid, got nil=%d invalid=%d", nilCount, invalidCount)
	}
}

func TestRemainingCounts(t *testing.T) {
	store := newMemStore()
	svc := mustService(t, store, WithCount(5))
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	remaining, err := svc.Remaining(ctx, "user1")
	if err != nil {
		t.Fatalf("Remaining: %v", err)
	}
	if remaining != 5 {
		t.Fatalf("expected 5 remaining, got %d", remaining)
	}

	if _, err := svc.Consume(ctx, "user1", codes[0]); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	remaining, err = svc.Remaining(ctx, "user1")
	if err != nil {
		t.Fatalf("Remaining: %v", err)
	}
	if remaining != 4 {
		t.Fatalf("expected 4 remaining, got %d", remaining)
	}
}

func TestDisableDeletesCodes(t *testing.T) {
	store := newMemStore()
	svc := mustService(t, store)
	ctx := context.Background()

	if _, err := svc.Generate(ctx, "user1"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.Disable(ctx, "user1"); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	remaining, err := svc.Remaining(ctx, "user1")
	if err != nil {
		t.Fatalf("Remaining: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("expected 0 remaining after Disable, got %d", remaining)
	}
}

func TestWithCountGeneratesRequestedNumber(t *testing.T) {
	store := newMemStore()
	svc := mustService(t, store, WithCount(3))
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(codes) != 3 {
		t.Fatalf("expected 3 codes, got %d", len(codes))
	}
}

// mustService builds a Service for a test that is not itself about
// construction failing. NewService returns an error since it began rejecting
// a nil store and a non-positive count.
func mustService(t *testing.T, store Store, opts ...Option) *Service {
	t.Helper()
	svc, err := NewService(store, opts...)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func TestNewServiceRejectsInvalidConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name    string
		store   Store
		opts    []Option
		wantErr string
	}{
		{"nil store", nil, nil, "store must not be nil"},
		{"zero count", newMemStore(), []Option{WithCount(0)}, "count must be positive"},
		{"negative count", newMemStore(), []Option{WithCount(-1)}, "count must be positive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, err := NewService(tc.store, tc.opts...)
			if err == nil {
				t.Fatal("NewService: expected an error, got nil")
			}
			if svc != nil {
				t.Fatalf("NewService: expected a nil service, got %#v", svc)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("NewService error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewServiceDefaultsToTenCodes(t *testing.T) {
	svc := mustService(t, newMemStore())

	codes, err := svc.Generate(context.Background(), "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(codes) != defaultCount {
		t.Fatalf("expected default %d codes, got %d", defaultCount, len(codes))
	}
}

// --- Consume's remaining count -----------------------------------------

func TestConsumeReportsRemainingCount(t *testing.T) {
	store := newMemStore()
	svc := mustService(t, store, WithCount(2))
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	remaining, err := svc.Consume(ctx, "user1", codes[0])
	if err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("first Consume: remaining = %d, want 1", remaining)
	}

	remaining, err = svc.Consume(ctx, "user1", codes[1])
	if err != nil {
		t.Fatalf("second (last) Consume: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("second (last) Consume: remaining = %d, want 0", remaining)
	}
}

func TestConsumeReturnsZeroRemainingOnRejection(t *testing.T) {
	store := newMemStore()
	svc := mustService(t, store)
	ctx := context.Background()

	if _, err := svc.Generate(ctx, "user1"); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	remaining, err := svc.Consume(ctx, "user1", "not-a-real-code")
	if !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("Consume(wrong code) error = %v, want ErrCodeInvalid", err)
	}
	if remaining != 0 {
		t.Fatalf("Consume(wrong code) remaining = %d, want 0", remaining)
	}
}

// failingConsumeStore wraps memStore and, on demand, fails ConsumeCode or
// ConsumeCode with a generic store error — distinct from ErrCodeNotFound,
// the store's normal "no such code" signal — used to exercise Consume's
// fail-closed propagation when the store itself misbehaves.
type failingConsumeStore struct {
	*memStore
	failConsume bool
}

func (f *failingConsumeStore) ConsumeCode(ctx context.Context, userID, hash string) (int, error) {
	if f.failConsume {
		return 0, errors.New("simulated store failure")
	}
	return f.memStore.ConsumeCode(ctx, userID, hash)
}

// TestConsumePropagatesConsumeCodeStoreError pins that a generic
// ConsumeCode failure (not ErrCodeNotFound) is returned to the caller
// unchanged, rather than being folded into ErrCodeInvalid.
func TestConsumePropagatesConsumeCodeStoreError(t *testing.T) {
	store := &failingConsumeStore{memStore: newMemStore(), failConsume: true}
	svc := mustService(t, store)
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	remaining, err := svc.Consume(ctx, "user1", codes[0])
	if err == nil || errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("Consume error = %v, want the raw store error propagated unchanged", err)
	}
	if remaining != 0 {
		t.Fatalf("Consume remaining = %d, want 0", remaining)
	}
}

// TestConsumeReturnsTheCountFromTheSameOperation pins that Consume reports
// the store's own remaining count rather than re-reading it. A store whose
// CountCodes lies proves the difference: only the value ConsumeCode returned
// may reach the caller.
func TestConsumeReturnsTheCountFromTheSameOperation(t *testing.T) {
	store := &lyingCountStore{memStore: newMemStore()}
	svc := mustService(t, store)
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	remaining, err := svc.Consume(ctx, "user1", codes[0])
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if remaining != len(codes)-1 {
		t.Fatalf("Consume remaining = %d, want %d from ConsumeCode itself", remaining, len(codes)-1)
	}
}

// lyingCountStore returns a deliberately wrong CountCodes, so any code path
// that still consults it after consuming fails loudly.
type lyingCountStore struct {
	*memStore
}

func (l *lyingCountStore) CountCodes(context.Context, string) (int, error) {
	return -42, nil
}

// --- The purge hook (Disable) -------------------------------------------

// TestConsumeAfterDisablePurgesTheCode pins Disable as the purge hook an
// application calls when the user's last OTHER second factor is removed
// (see Disable's doc comment): once called, no code from the purged set may
// authenticate anyone, and Consume must report zero remaining alongside
// ErrCodeInvalid rather than some stale prior count.
func TestConsumeAfterDisablePurgesTheCode(t *testing.T) {
	store := newMemStore()
	svc := mustService(t, store)
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if err := svc.Disable(ctx, "user1"); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	remaining, err := svc.Consume(ctx, "user1", codes[0])
	if !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("Consume after Disable error = %v, want ErrCodeInvalid — a purged code must not authenticate anyone", err)
	}
	if remaining != 0 {
		t.Fatalf("Consume after Disable remaining = %d, want 0", remaining)
	}
}

// --- The rate limiter ----------------------------------------------------

// fakeLimiter records every key it is asked about and denies (returning a
// generic error) whenever denied is true. Mirrors totp's own fakeLimiter
// test double exactly (totp/totp_test.go).
type fakeLimiter struct {
	mu     sync.Mutex
	keys   []string
	denied bool
}

func (f *fakeLimiter) Allow(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = append(f.keys, key)
	if f.denied {
		return errors.New("denied")
	}
	return nil
}

func (f *fakeLimiter) sawKey(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range f.keys {
		if k == key {
			return true
		}
	}
	return false
}

// TestConsumeConsultsLimiterBeforeCheckingCode mirrors totp's
// TestValidateConsultsLimiterBeforeCheckingCode: a denied limiter refuses
// the attempt — normalized to ErrCodeRateLimited — before the store is
// ever touched, so the code is still there to use once the limiter allows.
func TestConsumeConsultsLimiterBeforeCheckingCode(t *testing.T) {
	store := newMemStore()
	limiter := &fakeLimiter{denied: true}
	svc := mustService(t, store, WithLimiter(limiter))
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	remaining, err := svc.Consume(ctx, "user1", codes[0])
	if !errors.Is(err, ErrCodeRateLimited) {
		t.Fatalf("Consume error = %v, want ErrCodeRateLimited", err)
	}
	if remaining != 0 {
		t.Fatalf("Consume remaining = %d, want 0", remaining)
	}
	if !limiter.sawKey("recovery:user1") {
		t.Fatalf("limiter keys = %v, want %q among them", limiter.keys, "recovery:user1")
	}

	// The limiter denied the attempt before the store was ever touched:
	// the code must still be there, unconsumed, once the limiter allows.
	limiter.denied = false
	if _, err := svc.Consume(ctx, "user1", codes[0]); err != nil {
		t.Fatalf("Consume after limiter allows: %v", err)
	}
}

// TestConsumeNilLimiterIsNoOp asserts that omitting WithLimiter (the
// default) never denies anything.
func TestConsumeNilLimiterIsNoOp(t *testing.T) {
	store := newMemStore()
	svc := mustService(t, store) // no WithLimiter
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := svc.Consume(ctx, "user1", codes[0]); err != nil {
		t.Fatalf("Consume with no limiter configured: %v", err)
	}
}
