package passkey

import (
	"context"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

// EventKind names one passkey security or operational decision. Values are
// stable, lowercase, dot-namespaced strings suitable for logs and metrics.
type EventKind string

const (
	EventRegistrationSucceeded        EventKind = "passkey.registration_succeeded"
	EventRegistrationRejected         EventKind = "passkey.registration_rejected"
	EventRegistrationChallengeExpired EventKind = "passkey.registration_challenge_expired"
	EventLoginSucceeded               EventKind = "passkey.login_succeeded"
	EventLoginRejected                EventKind = "passkey.login_rejected"
	EventLoginChallengeExpired        EventKind = "passkey.login_challenge_expired"
	EventCloneWarning                 EventKind = "passkey.clone_warning"
	EventCredentialDeleted            EventKind = "passkey.credential_deleted"           // #nosec G101 -- an event label, not a credential
	EventCredentialDeletionRejected   EventKind = "passkey.credential_deletion_rejected" // #nosec G101 -- an event label, not a credential
	EventStoreFailed                  EventKind = "passkey.store_failed"
)

// Event is one passkey security or operational decision, as reported to an
// EventSink. It deliberately contains only opaque account identifiers and
// closed-category labels. It has no field for a challenge, response body,
// credential ID, public key, store error, or protocol diagnostic text.
type Event struct {
	Kind EventKind

	// UserID identifies the account when the ceremony has resolved one. It is
	// empty for an operation that fails before an account can be identified.
	UserID string

	// Operation identifies the store operation for EventStoreFailed. It is
	// empty for other event kinds.
	Operation string

	// Diagnostic is a category, not an error message. For protocol failures it
	// is protocol.Error.Type (for example, "invalid_request"); for local
	// failures it is a fixed category such as "session_data" or
	// "clone_warning". DevInfo and Details are intentionally excluded.
	Diagnostic string

	// At is when the decision was made, stamped at emission if left zero.
	At time.Time
}

// EventSink receives passkey security events. Emit must be safe for concurrent
// use and should return quickly; it runs on the ceremony's caller goroutine.
// A sink panic is contained by the Service and cannot change the ceremony's
// result.
type EventSink interface {
	Emit(ctx context.Context, e Event)
}

// emit delivers e to the configured sink, if any. It is the only way this
// package emits an event. A nil sink is a no-op and a panicking sink is
// contained so observability cannot change an authentication decision.
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

// diagnosticCategory extracts only go-webauthn's stable error category. The
// underlying protocol.Error remains available to callers when the returned
// error wraps it, but event sinks never receive DevInfo, Details, or Error().
func diagnosticCategory(err error) string {
	var protocolErr *protocol.Error
	if errors.As(err, &protocolErr) && protocolErr != nil && protocolErr.Type != "" {
		return protocolErr.Type
	}
	return "unknown"
}

func deletionDiagnostic(err error) string {
	switch {
	case errors.Is(err, ErrPasskeyNotFound):
		return "not_found"
	case errors.Is(err, ErrLastCredential):
		return "last_credential"
	default:
		return "unknown"
	}
}
