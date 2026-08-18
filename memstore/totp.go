package memstore

import (
	"context"
	"errors"
	"sync"

	"github.com/borfast/sulis/totp"
)

// ErrTOTPCounterRegressed is returned by TOTPStore.SaveTOTP when a save would
// lower LastUsedCounter for the active credential with the same ID. totp.Store
// requires such a save to be rejected but does not name the error; failing
// closed is the point, since a counter that can regress is a code that can be
// replayed.
var ErrTOTPCounterRegressed = errors.New("memstore: TOTP counter would regress")

// TOTPStore is an in-memory totp.Store.
//
// The two slots the interface describes are two maps: at most one active
// (verified) credential and at most one pending (unverified) enrollment per
// user. Keeping them separate is what stops a stray or racing enrollment from
// replacing a working second factor; the mutex is what makes each transition
// between them a single step.
type TOTPStore struct {
	mu      sync.Mutex
	active  map[string]*totp.Credential
	pending map[string]*totp.Credential
}

var _ totp.Store = (*TOTPStore)(nil)

// NewTOTPStore returns an empty TOTPStore.
func NewTOTPStore() *TOTPStore {
	return &TOTPStore{
		active:  make(map[string]*totp.Credential),
		pending: make(map[string]*totp.Credential),
	}
}

// GetActiveTOTP returns a copy of userID's active (verified) credential, or
// totp.ErrTOTPNotEnrolled — whether or not a pending enrollment exists.
func (s *TOTPStore) GetActiveTOTP(_ context.Context, userID string) (*totp.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred, ok := s.active[userID]
	if !ok {
		return nil, totp.ErrTOTPNotEnrolled
	}
	cp := *cred
	return &cp, nil
}

// GetPendingTOTP returns a copy of userID's pending (unverified) enrollment,
// or totp.ErrTOTPNotEnrolled.
func (s *TOTPStore) GetPendingTOTP(_ context.Context, userID string) (*totp.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred, ok := s.pending[userID]
	if !ok {
		return nil, totp.ErrTOTPNotEnrolled
	}
	cp := *cred
	return &cp, nil
}

// EnrollPending stores cred as userID's pending enrollment, but only if the
// user has no active credential: otherwise it returns
// totp.ErrTOTPAlreadyEnrolled and writes nothing. Callers that mean to
// supersede a working factor use ReplacePending instead.
//
// The check and the write are one critical section. Split them and a
// concurrent ConfirmEnrollment could promote a different pending enrollment
// to active in the gap, only for this write to land undetected right after —
// silently replacing a factor the user is relying on.
func (s *TOTPStore) EnrollPending(_ context.Context, cred *totp.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.active[cred.UserID]; ok {
		return totp.ErrTOTPAlreadyEnrolled
	}
	s.setPendingLocked(cred)
	return nil
}

// ReplacePending is EnrollPending without the active-credential guard: it
// stores cred as userID's pending enrollment whatever else is on file, and
// leaves any active credential completely alone, so codes keep validating
// against the old factor until a later ConfirmEnrollment promotes this one.
func (s *TOTPStore) ReplacePending(_ context.Context, cred *totp.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.setPendingLocked(cred)
	return nil
}

// ConfirmEnrollment promotes userID's pending enrollment to active, but only
// while it is still the one named by pendingID — the enrollment whose secret
// the caller just matched a code against. A mismatch means it was already
// promoted, or superseded by a racing enrollment, or never existed:
// totp.ErrTOTPNotEnrolled, and nothing is touched.
//
// The comparison and the promotion are one critical section, which is what
// closes the clobber race: otherwise an EnrollPending landing between Service
// reading the pending enrollment and this write would leave the store
// promoting a secret nobody validated, or discarding a fresh enrollment,
// without either caller finding out.
//
// counter is the time step the code was matched at. When an active credential
// already exists — a replacement rather than a first enrollment — the
// promoted credential keeps whichever counter is higher, so swapping factors
// can never roll the user's replay-protection clock backwards.
func (s *TOTPStore) ConfirmEnrollment(_ context.Context, userID, pendingID string, counter uint64) (*totp.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pending, ok := s.pending[userID]
	if !ok || pending.ID != pendingID {
		return nil, totp.ErrTOTPNotEnrolled
	}
	if active, ok := s.active[userID]; ok && active.LastUsedCounter > counter {
		counter = active.LastUsedCounter
	}

	promoted := &totp.Credential{
		ID:              pending.ID,
		UserID:          userID,
		Secret:          pending.Secret,
		Verified:        true,
		LastUsedCounter: counter,
		CreatedAt:       pending.CreatedAt,
	}
	s.active[userID] = promoted
	delete(s.pending, userID)

	cp := *promoted
	return &cp, nil
}

// SaveTOTP persists an update to an existing active credential — in practice
// the LastUsedCounter bump after a code is accepted. A save that would lower
// the counter for the active credential with the same ID is refused with
// ErrTOTPCounterRegressed rather than applied, so of two racing validations
// only one can advance the clock and the loser cannot rewind it.
func (s *TOTPStore) SaveTOTP(_ context.Context, cred *totp.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.active[cred.UserID]; ok {
		if existing.ID == cred.ID && cred.LastUsedCounter < existing.LastUsedCounter {
			return ErrTOTPCounterRegressed
		}
	}
	cp := *cred
	s.active[cred.UserID] = &cp
	return nil
}

// DeleteTOTP removes userID's active credential and any pending enrollment,
// both in one step. Removing them one after the other would let a concurrent
// ConfirmEnrollment promotion land in the gap, leaving the just-promoted
// credential behind as an active factor the caller believed it had removed.
func (s *TOTPStore) DeleteTOTP(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.active, userID)
	delete(s.pending, userID)
	return nil
}

// setPendingLocked stores a copy of cred as its user's pending enrollment,
// superseding whatever was there: at most one pending enrollment exists per
// user, and an unconfirmed one has nothing worth protecting. Callers must
// hold s.mu.
func (s *TOTPStore) setPendingLocked(cred *totp.Credential) {
	cp := *cred
	cp.Verified = false
	s.pending[cred.UserID] = &cp
}
