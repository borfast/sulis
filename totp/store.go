package totp

import (
	"context"
	"time"
)

// Credential represents a user's TOTP enrollment — either the active
// (verified) factor Validate checks codes against, or a pending
// (unverified) enrollment awaiting ConfirmEnrollment. Which one a given
// Credential is depends on which Store method returned it (GetActiveTOTP
// vs GetPendingTOTP), not on any field here: Verified is true on every
// Credential GetActiveTOTP returns and false on every Credential
// GetPendingTOTP returns.
type Credential struct {
	ID              string
	UserID          string
	Secret          string // base32-encoded shared secret
	Verified        bool   // true after the user confirms enrollment with a valid code
	LastUsedCounter uint64 // time-step counter of the last accepted code, for replay protection
	CreatedAt       time.Time
}

// Store defines the persistence operations for TOTP credentials. It keeps
// a user's active (verified) factor and pending (unverified) enrollment as
// two distinct slots — at most one of each per user — so that a stray or
// racing enrollment attempt can never silently replace an already-verified
// factor. EnrollPending and ConfirmEnrollment below document exactly where
// the atomicity that separation depends on must live.
type Store interface {
	// GetActiveTOTP returns userID's active (verified) credential — the
	// one Validate checks codes against. Returns ErrTOTPNotEnrolled if
	// userID has no active credential, whether or not a pending
	// enrollment exists.
	GetActiveTOTP(ctx context.Context, userID string) (*Credential, error)

	// GetPendingTOTP returns userID's pending (unverified) enrollment
	// awaiting ConfirmEnrollment, if any. Returns ErrTOTPNotEnrolled if
	// none exists.
	GetPendingTOTP(ctx context.Context, userID string) (*Credential, error)

	// EnrollPending atomically stores cred as userID's new pending
	// enrollment, after first checking that userID has no active
	// credential. The check and the write MUST happen as a single atomic
	// operation with respect to any concurrent call for the same userID —
	// the same requirement TokenStore.ConsumeToken,
	// ChallengeStore.ConsumeChallenge, and passkey.Store.DeleteCredential
	// already place on their own check-and-mutate operations, for the same
	// reason: a separate read-then-write would let a concurrent
	// ConfirmEnrollment promote some OTHER pending enrollment to active in
	// the gap between this method's check and its write, only for this
	// write to land undetected immediately after.
	//
	// Returns ErrTOTPAlreadyEnrolled if userID already has an active
	// credential; Service.Enroll surfaces this unchanged. Use
	// ReplacePending instead when the caller explicitly intends to
	// supersede an existing active credential.
	//
	// Any pending enrollment already on file for userID is unconditionally
	// superseded either way — at most one pending enrollment exists per
	// user, and an unconfirmed enrollment has nothing worth protecting.
	//
	// Reference SQL: run the existence check and the upsert as one
	// statement or inside one transaction, e.g.
	//
	//	INSERT INTO totp_pending (user_id, id, secret, created_at)
	//	SELECT $1, $2, $3, $4
	//	WHERE NOT EXISTS (
	//	    SELECT 1 FROM totp_active WHERE user_id = $1
	//	)
	//	ON CONFLICT (user_id) DO UPDATE
	//	  SET id = EXCLUDED.id, secret = EXCLUDED.secret, created_at = EXCLUDED.created_at
	//
	// and check the affected-row count: 0 rows means an active credential
	// already exists, so return ErrTOTPAlreadyEnrolled instead of treating
	// it as a generic no-op. A single-threaded or mutex-guarded in-memory
	// store can simply perform the check and the write while holding the
	// same lock.
	EnrollPending(ctx context.Context, cred *Credential) error

	// ReplacePending is EnrollPending without the active-credential guard:
	// it unconditionally stores cred as userID's new pending enrollment,
	// whether or not an active credential exists, and leaves any existing
	// active credential completely untouched — Validate keeps checking
	// codes against it until a later ConfirmEnrollment promotes cred. This
	// is the explicit "I already have a factor and I mean to replace it"
	// path Service.ReplaceEnrollment uses.
	ReplacePending(ctx context.Context, cred *Credential) error

	// ConfirmEnrollment atomically promotes userID's pending enrollment to
	// active — but only if it is still the exact enrollment identified by
	// pendingID, the ID of the pending credential the caller fetched (via
	// GetPendingTOTP) and validated a code against. Implementations MUST
	// perform the ID comparison and the promotion (remove the pending
	// enrollment, install it as active) as one atomic operation with
	// respect to any concurrent call for the same userID — the same
	// requirement TokenStore.ConsumeToken, ChallengeStore.ConsumeChallenge,
	// and passkey.Store.DeleteCredential place on their own
	// check-and-mutate operations. Without it, a concurrent EnrollPending
	// or ReplacePending call could overwrite userID's pending enrollment in
	// the gap between Service.ConfirmEnrollment reading it (to validate a
	// code against its secret) and this method committing the promotion —
	// this method would then either promote a pending enrollment nobody
	// actually validated a code against, or silently discard a fresh
	// enrollment attempt that landed in that gap, without either caller
	// ever finding out. This is the atomic operation that closes the
	// clobber race described in the T302 task brief.
	//
	// counter is the time-step counter Service has already matched the
	// submitted code against, for the pending credential's own secret. If
	// userID already has an active credential (ConfirmEnrollment is
	// confirming a ReplaceEnrollment, not a first enrollment), the
	// promoted credential's LastUsedCounter MUST be set to whichever is
	// greater of counter and the prior active credential's
	// LastUsedCounter — never lower — so that replacing a factor can never
	// roll a user's replay-protection clock backward.
	//
	// Returns ErrTOTPNotEnrolled if userID's current pending enrollment's
	// ID no longer matches pendingID — already promoted by a concurrent
	// call, superseded by a racing EnrollPending/ReplacePending, or never
	// existed. The caller treats this exactly like "nothing to confirm."
	//
	// Reference SQL, in one transaction:
	//
	//	WITH moved AS (
	//	  DELETE FROM totp_pending WHERE user_id = $1 AND id = $2
	//	  RETURNING id, secret, created_at
	//	)
	//	INSERT INTO totp_active (user_id, id, secret, verified, last_used_counter, created_at)
	//	SELECT $1, moved.id, moved.secret, true,
	//	       GREATEST($3, COALESCE(
	//	           (SELECT last_used_counter FROM totp_active WHERE user_id = $1), 0)),
	//	       moved.created_at
	//	FROM moved
	//	ON CONFLICT (user_id) DO UPDATE
	//	  SET id = EXCLUDED.id, secret = EXCLUDED.secret, verified = true,
	//	      last_used_counter = EXCLUDED.last_used_counter
	//
	// Check the DELETE's affected-row count: 0 rows means pendingID no
	// longer matches, so return ErrTOTPNotEnrolled without touching
	// totp_active.
	ConfirmEnrollment(ctx context.Context, userID, pendingID string, counter uint64) (*Credential, error)

	// SaveTOTP persists an update to an existing ACTIVE credential — in
	// practice, Validate's post-check LastUsedCounter bump. Implementations
	// MUST persist LastUsedCounter atomically with respect to concurrent
	// calls, and MUST reject (fail closed) any save that would lower
	// LastUsedCounter for the active credential with the same ID, so two
	// racing validates cannot both win.
	SaveTOTP(ctx context.Context, cred *Credential) error

	// DeleteTOTP removes both userID's active credential and any pending
	// enrollment.
	DeleteTOTP(ctx context.Context, userID string) error
}
