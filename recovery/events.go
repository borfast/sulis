package recovery

import (
	"context"
	"time"
)

// Security events.
//
// This file discharges the carry-forward recorded at T509 (see PROGRESS.md):
// recovery-code use was the one security decision the sulis module could not
// yet observe, because the root package's event sink (events.go) only wires
// through the root package's own flows and this subpackage has no
// dependency on it.
//
// # Why this can't reuse sulis.Limiter's trick
//
// totp.Limiter and this package's own Limiter (recovery.go) are declared
// with an identical method set to sulis.Limiter — Allow(ctx, key string)
// error — so a single sulis.MemoryLimiter instance satisfies all three via
// Go's structural interface typing, with no import in either direction:
// the signature carries only primitives (a string key, an error).
//
// EventSink cannot repeat that trick, and this file's separate taxonomy is
// not an oversight. Emit's payload is Event, and Event is a distinct named
// type in every package that declares one (sulis.Event here would be
// recovery.Event). Go resolves interface satisfaction by the method's exact
// parameter type, not by structural equivalence of that parameter's own
// fields, so no single Emit method can simultaneously take sulis.Event and
// recovery.Event — unlike a bare string, a struct type doesn't get to be
// "the same shape" across packages without literally being the same type.
// Importing sulis.Event here to force that would defeat the entire reason
// this package declares its own Limiter instead of importing sulis.Limiter:
// recovery must not depend on the root module.
//
// So recovery ships its own independent EventKind/Event/EventSink/
// WithEventSink, mirroring root's DESIGN — a closed, dot-namespaced
// taxonomy; a payload with no field that could hold a secret; a nil
// default; a contained sink panic — without pretending to be
// wire-compatible with it. An application that wants one unified event
// stream writes a small adapter translating a recovery.Event into whatever
// shape its own sink expects (a sulis.Event, a log line, a metric) and
// registers it via both packages' WithEventSink.

// EventKind names one recovery-code security decision. The values are
// stable, lowercase, dot-namespaced strings — the same shape as the root
// package's EventKind — safe to use as log field values, metric labels, or
// database enum entries.
//
// Each constant repeats the EventKind type deliberately, rather than
// leaning on a const block carrying the type down the list, so a
// completeness test can find every declaration by scanning this file's
// source the same way events_test.go's TestEveryDeclaredEventKindIsEmitted
// does for the root package.
type EventKind string

const (
	// EventCodeConsumed reports that Consume accepted a code. Remaining is
	// how many unused codes are left for the user afterward.
	EventCodeConsumed EventKind = "recovery.code_consumed"

	// EventCodeRejected reports that Consume refused a code that did not
	// match any stored, unused code for the user (ErrCodeInvalid). It is
	// NOT emitted for a rate-limited attempt (see WithLimiter, which
	// returns ErrCodeRateLimited before the store is ever touched) or for
	// a Store error — only for a code that was actually checked and did
	// not match.
	EventCodeRejected EventKind = "recovery.code_rejected"

	// EventCodesExhausted reports that a successful Consume left the user
	// with zero unused codes. It is emitted IN ADDITION to
	// EventCodeConsumed for that same call — "a code was used" and "there
	// are none left" are two distinct facts, and the second is what an
	// application should treat as its signal to push the user toward
	// re-enrolling a real second factor.
	EventCodesExhausted EventKind = "recovery.codes_exhausted"
)

// Event is one recovery-code security decision, as reported to an
// EventSink.
//
// There is deliberately no field that could carry a code or its hash — not
// the plaintext the user typed, not the SHA-256 hex digest compared against
// the store. That is enforced by the type, the same way sulis.Event has no
// such field: there is nothing here to forget to omit.
type Event struct {
	// Kind is which decision this is. Always set.
	Kind EventKind

	// UserID is the account the decision concerns.
	UserID string

	// Remaining is the number of unused codes left for UserID after the
	// decision. Meaningful for EventCodeConsumed; zero (and not
	// meaningful) for EventCodeRejected and EventCodesExhausted, which
	// carry the fact in their Kind instead.
	Remaining int

	// At is when the decision was made, stamped at emission if left zero.
	At time.Time
}

// EventSink receives recovery-code security events.
//
// Emit returns nothing: a sink has no way to fail Consume, so there is no
// error for this package to propagate and no temptation to propagate one.
// Implementations must be safe for concurrent use, and should return
// quickly — Emit runs on the caller's goroutine, inside Consume's latency
// budget. A sink that panics is contained by emit (see recovery.go) for the
// same reason sulis's own emit contains one: an observability hook must not
// be able to deny (or silently allow) a recovery-code attempt.
type EventSink interface {
	Emit(ctx context.Context, e Event)
}

// emit delivers e to the configured sink, if there is one, stamping At if
// it is zero. It is the only way this package produces an event.
//
// The nil-sink check comes first and nothing before it allocates, so an
// unconfigured Service pays one comparison and nothing else — Event here
// has no map field to build lazily the way sulis.emit's metaPairs trick
// exists for, so there is no equivalent lazy-construction hazard to guard
// against.
//
// A panicking sink is recovered and dropped rather than allowed to unwind
// Consume — this is an auth library, and an observability hook must not be
// able to turn a legitimate recovery-code use into a failed one (or vice
// versa, by panicking after the store mutation already committed). That
// containment is a backstop for a buggy sink, not a licence to write one:
// a recovered panic here is silent, because there is nowhere left to
// report it to.
func (s *Service) emit(ctx context.Context, e Event) {
	if s.cfg.EventSink == nil {
		return
	}
	if e.At.IsZero() {
		e.At = time.Now()
	}
	defer func() { _ = recover() }()
	s.cfg.EventSink.Emit(ctx, e)
}
