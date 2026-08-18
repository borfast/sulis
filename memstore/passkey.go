package memstore

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/borfast/sulis/passkey"
)

// ErrChallengeNotFound is returned by ChallengeStore.ConsumeChallenge when no
// challenge is stored under the key — already consumed, or never saved.
// passkey.ChallengeStore leaves this error implementation-defined; the
// caller normalizes whatever comes back to passkey.ErrChallengeExpired.
var ErrChallengeNotFound = errors.New("memstore: challenge not found")

// PasskeyStore is an in-memory passkey.Store.
//
// Credentials are held in one map keyed by passkey.Credential.ID, the store's
// own opaque identifier, and looked up by raw WebAuthn credential ID with a
// scan. A real store indexes both columns; keeping one map here means there
// is no second index to fall out of step with the first, which is the bug
// that makes a passkey unusable after a rename or a sign-count update.
type PasskeyStore struct {
	mu    sync.Mutex
	creds map[string]*passkey.Credential
}

var _ passkey.Store = (*PasskeyStore)(nil)

// NewPasskeyStore returns an empty PasskeyStore.
func NewPasskeyStore() *PasskeyStore {
	return &PasskeyStore{creds: make(map[string]*passkey.Credential)}
}

// SaveCredential stores a deep copy of cred, keyed by cred.ID.
func (s *PasskeyStore) SaveCredential(_ context.Context, cred *passkey.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.creds[cred.ID] = cloneCredential(cred)
	return nil
}

// GetCredentialsByUserID returns copies of every credential owned by userID.
// A user with no credentials is not an error: it is how a caller learns the
// user has no passkey enrolled.
func (s *PasskeyStore) GetCredentialsByUserID(_ context.Context, userID string) ([]passkey.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []passkey.Credential
	for _, cred := range s.creds {
		if cred.UserID == userID {
			out = append(out, *cloneCredential(cred))
		}
	}
	return out, nil
}

// GetCredentialByID returns a copy of the credential whose raw WebAuthn
// credential ID is credentialID, or passkey.ErrPasskeyNotFound.
func (s *PasskeyStore) GetCredentialByID(_ context.Context, credentialID []byte) (*passkey.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred := s.byCredentialIDLocked(credentialID)
	if cred == nil {
		return nil, passkey.ErrPasskeyNotFound
	}
	return cloneCredential(cred), nil
}

// UpdateCredentialAfterLogin persists the three fields that must change
// together on every successful assertion: SignCount, BackupState, and
// LastUsedAt. go-webauthn re-reads all three on the next ceremony, so a store
// that persists only some of them breaks the credential's next login rather
// than this one.
func (s *PasskeyStore) UpdateCredentialAfterLogin(_ context.Context, credentialID []byte, signCount uint32, backupState bool, lastUsedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred := s.byCredentialIDLocked(credentialID)
	if cred == nil {
		return passkey.ErrPasskeyNotFound
	}
	when := lastUsedAt
	cred.SignCount = signCount
	cred.BackupState = backupState
	cred.LastUsedAt = &when
	return nil
}

// DeleteCredential removes the credential named by id if it belongs to
// userID, refusing with passkey.ErrLastCredential when it is the user's only
// remaining credential and allowLast is false, and reporting
// passkey.ErrPasskeyNotFound when id names no credential of that user's.
//
// The ownership check, the remaining-count check, and the removal all happen
// while holding s.mu, which is the whole point. Split them and two goroutines
// each deleting one of a user's last two credentials both see count == 2,
// both pass the guard, and both succeed — leaving the user locked out through
// the path that exists to prevent exactly that. A SQL store gets the same
// effect from one conditional DELETE, or from a transaction that locks the
// user's credential rows before counting them.
func (s *PasskeyStore) DeleteCredential(_ context.Context, userID, id string, allowLast bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred, ok := s.creds[id]
	if !ok || cred.UserID != userID {
		return passkey.ErrPasskeyNotFound
	}
	if !allowLast && s.countByUserLocked(userID) <= 1 {
		return passkey.ErrLastCredential
	}
	delete(s.creds, id)
	return nil
}

// DeleteCredentialsByUserID removes every credential owned by userID. The
// last-credential guard deliberately does not apply: deleting a whole account
// is a stronger action the caller has already gated, and leaving one
// credential behind because it happened to be last would be surprising.
func (s *PasskeyStore) DeleteCredentialsByUserID(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, cred := range s.creds {
		if cred.UserID == userID {
			delete(s.creds, id)
		}
	}
	return nil
}

// RenameCredential sets the caller-supplied display name on the credential
// named by id, or returns passkey.ErrPasskeyNotFound. The name is stored
// verbatim: passkey never generates, infers, or validates it.
func (s *PasskeyStore) RenameCredential(_ context.Context, id, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred, ok := s.creds[id]
	if !ok {
		return passkey.ErrPasskeyNotFound
	}
	cred.Name = name
	return nil
}

// byCredentialIDLocked returns the stored credential with the given raw
// WebAuthn credential ID, or nil. Callers must hold s.mu.
func (s *PasskeyStore) byCredentialIDLocked(credentialID []byte) *passkey.Credential {
	for _, cred := range s.creds {
		if bytes.Equal(cred.CredentialID, credentialID) {
			return cred
		}
	}
	return nil
}

// countByUserLocked reports how many credentials userID owns. Callers must
// hold s.mu.
func (s *PasskeyStore) countByUserLocked(userID string) int {
	n := 0
	for _, cred := range s.creds {
		if cred.UserID == userID {
			n++
		}
	}
	return n
}

// cloneCredential deep-copies a credential, so neither the caller's slices
// nor the store's can be mutated through the other.
func cloneCredential(cred *passkey.Credential) *passkey.Credential {
	cp := *cred
	cp.CredentialID = bytes.Clone(cred.CredentialID)
	cp.PublicKey = bytes.Clone(cred.PublicKey)
	cp.AAGUID = bytes.Clone(cred.AAGUID)
	if cred.Transports != nil {
		cp.Transports = append(cp.Transports[:0:0], cred.Transports...)
	}
	if cred.LastUsedAt != nil {
		when := *cred.LastUsedAt
		cp.LastUsedAt = &when
	}
	return &cp
}

// ChallengeStore is an in-memory passkey.ChallengeStore.
//
// It does not expire entries. A production implementation should, after
// roughly five minutes — the lifetime of a WebAuthn ceremony — which is one
// line in Redis and a scheduled delete in SQL.
type ChallengeStore struct {
	mu         sync.Mutex
	challenges map[string][]byte
}

var _ passkey.ChallengeStore = (*ChallengeStore)(nil)

// NewChallengeStore returns an empty ChallengeStore.
func NewChallengeStore() *ChallengeStore {
	return &ChallengeStore{challenges: make(map[string][]byte)}
}

// SaveChallenge stores a copy of sessionData under key, replacing anything
// already there. The copy matters: a caller reusing its buffer must not be
// able to rewrite a challenge it has already handed over.
func (s *ChallengeStore) SaveChallenge(_ context.Context, key string, sessionData []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.challenges[key] = bytes.Clone(sessionData)
	return nil
}

// ConsumeChallenge fetches and deletes the challenge stored under key in one
// operation, so two concurrent finishes of the same ceremony can never both
// receive it — the in-memory equivalent of Redis GETDEL or SQL
// "DELETE ... RETURNING". Returns ErrChallengeNotFound if there is nothing
// under key.
func (s *ChallengeStore) ConsumeChallenge(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, ok := s.challenges[key]
	if !ok {
		return nil, ErrChallengeNotFound
	}
	delete(s.challenges, key)
	return bytes.Clone(data), nil
}
