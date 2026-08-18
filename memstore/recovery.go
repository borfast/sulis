package memstore

import (
	"context"
	"sync"

	"github.com/borfast/sulis/recovery"
)

// RecoveryStore is an in-memory recovery.Store.
//
// Codes are held per user as a set of hashes. The plaintext codes are never
// stored — recovery hashes them before they reach any store, and this one has
// nothing to hash back.
type RecoveryStore struct {
	mu    sync.Mutex
	codes map[string]map[string]struct{}
}

var _ recovery.Store = (*RecoveryStore)(nil)

// NewRecoveryStore returns an empty RecoveryStore.
func NewRecoveryStore() *RecoveryStore {
	return &RecoveryStore{codes: make(map[string]map[string]struct{})}
}

// ReplaceCodes swaps userID's whole code set for hashes in one step, so a
// regeneration never leaves a caller looking at a half-replaced set — some
// codes from the old batch and some from the new. An empty or nil slice
// clears the set.
func (s *RecoveryStore) ReplaceCodes(_ context.Context, userID string, hashes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	set := make(map[string]struct{}, len(hashes))
	for _, h := range hashes {
		set[h] = struct{}{}
	}
	s.codes[userID] = set
	return nil
}

// ConsumeCode finds and deletes the code matching userID and hash in one
// step, returning recovery.ErrCodeNotFound when there is no such unused code
// for that user. A recovery code bypasses every other factor, so a store that
// looked the code up and then deleted it would let two concurrent
// presentations of the same code both authenticate.
func (s *RecoveryStore) ConsumeCode(_ context.Context, userID, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	set, ok := s.codes[userID]
	if !ok {
		return recovery.ErrCodeNotFound
	}
	if _, ok := set[hash]; !ok {
		return recovery.ErrCodeNotFound
	}
	delete(set, hash)
	return nil
}

// CountCodes reports how many unused codes userID has left. A user with none
// counts zero rather than erroring.
func (s *RecoveryStore) CountCodes(_ context.Context, userID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.codes[userID]), nil
}

// DeleteCodes removes every code for userID.
func (s *RecoveryStore) DeleteCodes(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.codes, userID)
	return nil
}
