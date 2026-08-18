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

func (m *memStore) ConsumeCode(_ context.Context, userID, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	set, ok := m.codes[userID]
	if !ok {
		return ErrCodeNotFound
	}
	if _, ok := set[hash]; !ok {
		return ErrCodeNotFound
	}
	delete(set, hash)
	return nil
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
	svc := NewService(store)
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
	svc := NewService(store)
	ctx := context.Background()

	oldCodes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate (first): %v", err)
	}
	newCodes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate (second): %v", err)
	}

	if err := svc.Consume(ctx, "user1", oldCodes[0]); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("Consume(old code): expected ErrCodeInvalid, got %v", err)
	}
	if err := svc.Consume(ctx, "user1", newCodes[0]); err != nil {
		t.Fatalf("Consume(new code): expected nil, got %v", err)
	}
}

func TestConsumeAcceptsSloppyInput(t *testing.T) {
	store := newMemStore()
	svc := NewService(store)
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sloppy := "  " + strings.ToUpper(strings.ReplaceAll(codes[0], "-", "")) + "  "

	if err := svc.Consume(ctx, "user1", sloppy); err != nil {
		t.Fatalf("Consume(sloppy): expected nil, got %v", err)
	}
}

func TestConsumeIsSingleUse(t *testing.T) {
	store := newMemStore()
	svc := NewService(store)
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := svc.Consume(ctx, "user1", codes[0]); err != nil {
		t.Fatalf("first Consume: expected nil, got %v", err)
	}
	if err := svc.Consume(ctx, "user1", codes[0]); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("second Consume: expected ErrCodeInvalid, got %v", err)
	}
}

func TestConcurrentConsumeSingleWinner(t *testing.T) {
	store := newMemStore()
	svc := NewService(store, WithCount(1))
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
			errs[i] = svc.Consume(ctx, "user1", code)
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
	svc := NewService(store, WithCount(5))
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

	if err := svc.Consume(ctx, "user1", codes[0]); err != nil {
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
	svc := NewService(store)
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
	svc := NewService(store, WithCount(3))
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(codes) != 3 {
		t.Fatalf("expected 3 codes, got %d", len(codes))
	}
}

func TestWithCountIgnoresNonPositiveValues(t *testing.T) {
	store := newMemStore()
	svc := NewService(store, WithCount(0))
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(codes) != defaultCount {
		t.Fatalf("expected default %d codes, got %d", defaultCount, len(codes))
	}
}
