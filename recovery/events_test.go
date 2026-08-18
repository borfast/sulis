package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// recordingSink collects every event Emit is called with, for assertions.
// Mirrors the root sulis package's recordingSink test double (events_test.go).
type recordingSink struct {
	mu     sync.Mutex
	events []Event
}

func (r *recordingSink) Emit(_ context.Context, e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recordingSink) all() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, len(r.events))
	copy(out, r.events)
	return out
}

func (r *recordingSink) kindsFor(userID string) []EventKind {
	var out []EventKind
	for _, e := range r.all() {
		if e.UserID == userID {
			out = append(out, e.Kind)
		}
	}
	return out
}

func TestConsumeEmitsCodeConsumedWithRemaining(t *testing.T) {
	store := newMemStore()
	sink := &recordingSink{}
	svc := NewService(store, WithCount(2), WithEventSink(sink))
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := svc.Consume(ctx, "user1", codes[0]); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	events := sink.all()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %+v", len(events), events)
	}
	if events[0].Kind != EventCodeConsumed {
		t.Fatalf("event kind = %q, want %q", events[0].Kind, EventCodeConsumed)
	}
	if events[0].UserID != "user1" {
		t.Fatalf("event UserID = %q, want %q", events[0].UserID, "user1")
	}
	if events[0].Remaining != 1 {
		t.Fatalf("event Remaining = %d, want 1", events[0].Remaining)
	}
	if events[0].At.IsZero() {
		t.Fatal("event At is zero, want stamped")
	}
}

func TestConsumeEmitsCodeRejectedOnInvalidCode(t *testing.T) {
	store := newMemStore()
	sink := &recordingSink{}
	svc := NewService(store, WithEventSink(sink))
	ctx := context.Background()

	if _, err := svc.Generate(ctx, "user1"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := svc.Consume(ctx, "user1", "not-a-real-code"); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("Consume error = %v, want ErrCodeInvalid", err)
	}

	events := sink.all()
	if len(events) != 1 || events[0].Kind != EventCodeRejected {
		t.Fatalf("events = %+v, want exactly one EventCodeRejected", events)
	}
	if events[0].UserID != "user1" {
		t.Fatalf("event UserID = %q, want %q", events[0].UserID, "user1")
	}
}

// TestConsumeEmitsCodesExhaustedOnTheLastCode pins that consuming the last
// remaining code emits BOTH EventCodeConsumed (the ordinary fact) and
// EventCodesExhausted (the actionable one) — see EventCodesExhausted's doc
// comment for why these are two distinct events rather than one.
func TestConsumeEmitsCodesExhaustedOnTheLastCode(t *testing.T) {
	store := newMemStore()
	sink := &recordingSink{}
	svc := NewService(store, WithCount(1), WithEventSink(sink))
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := svc.Consume(ctx, "user1", codes[0]); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	kinds := sink.kindsFor("user1")
	if len(kinds) != 2 {
		t.Fatalf("got %d events for user1, want 2 (consumed + exhausted): %v", len(kinds), kinds)
	}
	if kinds[0] != EventCodeConsumed || kinds[1] != EventCodesExhausted {
		t.Fatalf("event kinds = %v, want [%q %q]", kinds, EventCodeConsumed, EventCodesExhausted)
	}
}

func TestConsumeDoesNotEmitExhaustedWhenCodesRemain(t *testing.T) {
	store := newMemStore()
	sink := &recordingSink{}
	svc := NewService(store, WithCount(2), WithEventSink(sink))
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := svc.Consume(ctx, "user1", codes[0]); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	for _, e := range sink.all() {
		if e.Kind == EventCodesExhausted {
			t.Fatalf("EventCodesExhausted emitted with a code still remaining")
		}
	}
}

func TestNilEventSinkIsANoOp(t *testing.T) {
	store := newMemStore()
	svc := NewService(store) // no WithEventSink
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := svc.Consume(ctx, "user1", codes[0]); err != nil {
		t.Fatalf("Consume with no sink configured: %v", err)
	}
}

// panicSink always panics, to prove emit contains it rather than letting it
// unwind Consume — the same guarantee the root package's emit makes.
type panicSink struct{}

func (panicSink) Emit(context.Context, Event) { panic("sink exploded") }

func TestEventSinkPanicDoesNotFailConsume(t *testing.T) {
	store := newMemStore()
	svc := NewService(store, WithEventSink(panicSink{}))
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := svc.Consume(ctx, "user1", codes[0]); err != nil {
		t.Fatalf("Consume: %v, want nil even though the sink panicked", err)
	}
}

// TestConsumeEmitsCodeRateLimitedOnDeniedAttempt mirrors
// TestConsumeEmitsCodeRejectedOnInvalidCode: a Limiter denial is a distinct
// security decision from an unmatched code, so it gets its own EventKind
// (EventCodeRateLimited) rather than silently producing no event at all —
// see EventCodeRateLimited's doc comment for why an operator watching only
// EventCodeRejected would otherwise never see rate-limited guessing.
func TestConsumeEmitsCodeRateLimitedOnDeniedAttempt(t *testing.T) {
	store := newMemStore()
	sink := &recordingSink{}
	limiter := &fakeLimiter{denied: true}
	svc := NewService(store, WithLimiter(limiter), WithEventSink(sink))
	ctx := context.Background()

	if _, err := svc.Generate(ctx, "user1"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := svc.Consume(ctx, "user1", "irrelevant-code"); !errors.Is(err, ErrCodeRateLimited) {
		t.Fatalf("Consume error = %v, want ErrCodeRateLimited", err)
	}

	events := sink.all()
	if len(events) != 1 || events[0].Kind != EventCodeRateLimited {
		t.Fatalf("events = %+v, want exactly one EventCodeRateLimited", events)
	}
	if events[0].UserID != "user1" {
		t.Fatalf("event UserID = %q, want %q", events[0].UserID, "user1")
	}
}

// --- Taxonomy completeness --------------------------------------------------

// TestEveryDeclaredRecoveryEventKindIsEmitted mirrors the root package's
// TestEveryDeclaredEventKindIsEmitted: it reads the EventKind constants out
// of events.go's source and fails if any is never emitted by a flow driven
// here, so a kind added later without a flow to emit it fails rather than
// shipping as a promise this package does not keep.
func TestEveryDeclaredRecoveryEventKindIsEmitted(t *testing.T) {
	declared := declaredRecoveryEventKinds(t)
	if len(declared) == 0 {
		t.Fatal("no EventKind constants found in events.go; the scan is broken")
	}

	store := newMemStore()
	sink := &recordingSink{}
	limiter := &fakeLimiter{}
	svc := NewService(store, WithCount(1), WithEventSink(sink), WithLimiter(limiter))
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	limiter.denied = true
	if _, err := svc.Consume(ctx, "user1", "wrong-code"); !errors.Is(err, ErrCodeRateLimited) {
		t.Fatalf("Consume(rate limited): %v", err)
	}
	limiter.denied = false

	if _, err := svc.Consume(ctx, "user1", "wrong-code"); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("Consume(wrong code): %v", err)
	}
	if _, err := svc.Consume(ctx, "user1", codes[0]); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	emitted := map[EventKind]bool{}
	for _, e := range sink.all() {
		emitted[e.Kind] = true
	}

	var missing []string
	for _, k := range declared {
		if !emitted[k] {
			missing = append(missing, string(k))
		}
	}
	if len(missing) > 0 {
		t.Fatalf("declared but never emitted: %s", strings.Join(missing, ", "))
	}
}

func declaredRecoveryEventKinds(t *testing.T) []EventKind {
	t.Helper()
	src, err := os.ReadFile("events.go")
	if err != nil {
		t.Fatalf("reading events.go: %v", err)
	}
	re := regexp.MustCompile(`(?m)^\s*Event\w+\s+EventKind\s*=\s*"([^"]+)"`)
	var out []EventKind
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		out = append(out, EventKind(m[1]))
	}
	return out
}

// --- The no-secrets property -------------------------------------------

// TestNoRecoveryEventCarriesTheCode drives Consume through a rate-limited
// denial, a rejection, and a success, then scans every emitted event for
// the plaintext codes and their hashes. Mirrors the root package's
// TestNoEventCarriesSecretMaterial (events_test.go).
func TestNoRecoveryEventCarriesTheCode(t *testing.T) {
	store := newMemStore()
	sink := &recordingSink{}
	limiter := &fakeLimiter{}
	svc := NewService(store, WithCount(1), WithEventSink(sink), WithLimiter(limiter))
	ctx := context.Background()

	codes, err := svc.Generate(ctx, "user1")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	secret := codes[0]
	secretHash := hashCode(secret)
	const wrongCode = "wrong-code-entirely"

	// A rate-limited attempt first, handing Consume the real secret so a
	// leak in EventCodeRateLimited's payload would be caught exactly like
	// the other two kinds below. The Limiter denies before the store is
	// ever touched, so the code is still unconsumed afterward.
	limiter.denied = true
	if _, err := svc.Consume(ctx, "user1", secret); !errors.Is(err, ErrCodeRateLimited) {
		t.Fatalf("Consume(rate limited): %v", err)
	}
	limiter.denied = false

	// A rejection next, so the wrong code (and its hash) is also in the
	// secret set the scan checks against — Consume must not echo back what
	// it was handed even when refusing it.
	if _, err := svc.Consume(ctx, "user1", wrongCode); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("Consume(wrong code): %v", err)
	}
	if _, err := svc.Consume(ctx, "user1", secret); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	events := sink.all()
	if len(events) == 0 {
		t.Fatal("no events emitted; the scan below would be vacuous")
	}

	secrets := []string{secret, secretHash, wrongCode, hashCode(wrongCode)}
	for i, e := range events {
		for _, secretValue := range secrets {
			if scanRecoveryEventFor(t, e, secretValue) {
				t.Errorf("event %d (%s) contains %q", i, e.Kind, secretValue)
			}
		}
	}
}

// TestRecoveryEventScanCatchesAPlantedSecret is the mutation-test control for
// the property above: it plants a secret in each field Event actually has
// and asserts the scanner notices. Without it, TestNoRecoveryEventCarriesTheCode
// could pass because the scanner is broken rather than because the events
// are clean.
func TestRecoveryEventScanCatchesAPlantedSecret(t *testing.T) {
	const secret = "s3cr3t-planted-value"

	for _, tc := range []struct {
		name  string
		event Event
	}{
		{"UserID", Event{Kind: EventCodeConsumed, UserID: secret}},
		{"Kind", Event{Kind: EventKind(secret)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !scanRecoveryEventFor(t, tc.event, secret) {
				t.Fatalf("the scanner missed a secret planted in %s; TestNoRecoveryEventCarriesTheCode cannot be trusted", tc.name)
			}
		})
	}

	if scanRecoveryEventFor(t, Event{Kind: EventCodeConsumed, UserID: "an-ordinary-id"}, secret) {
		t.Fatal("the scanner reports a secret in an event that has none")
	}
}

// scanRecoveryEventFor reports whether e carries secret anywhere, using two
// independent renderings — encoding/json (what a sink would realistically
// serialize) and %#v (the raw Go value) — so a field added later is caught
// by at least one of them without this test being updated.
func scanRecoveryEventFor(t *testing.T, e Event, secret string) bool {
	t.Helper()
	if secret == "" {
		t.Fatal("scanRecoveryEventFor: empty secret; the scan would match everything")
	}
	encoded, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshalling event: %v", err)
	}
	haystack := string(encoded) + "\n" + fmt.Sprintf("%#v", e)
	return strings.Contains(haystack, secret) ||
		strings.Contains(strings.ToLower(haystack), strings.ToLower(secret))
}
