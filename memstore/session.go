package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/borfast/sulis"
)

// SessionStore is an in-memory sulis.SessionStore.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*sulis.Session
}

var _ sulis.SessionStore = (*SessionStore)(nil)

// NewSessionStore returns an empty SessionStore.
func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[string]*sulis.Session)}
}

// CreateSession stores a copy of session, keyed by its ID.
func (s *SessionStore) CreateSession(_ context.Context, session *sulis.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cp := *session
	s.sessions[session.ID] = &cp
	return nil
}

// GetSessionByTokenHash returns a copy of the session whose TokenHash is
// tokenHash, or sulis.ErrSessionNotFound. Only the hash is ever stored or
// compared; sulis never hands a store the raw token.
func (s *SessionStore) GetSessionByTokenHash(_ context.Context, tokenHash string) (*sulis.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, sess := range s.sessions {
		if sess.TokenHash == tokenHash {
			cp := *sess
			return &cp, nil
		}
	}
	return nil, sulis.ErrSessionNotFound
}

// DeleteSession removes the session identified by id only if it belongs to
// userID, and returns sulis.ErrSessionNotFound when nothing matched — whether
// id names no session at all or one owned by somebody else. This is the
// equivalent of "DELETE FROM sessions WHERE id = ? AND user_id = ?" plus a
// check of the affected-row count, and it is what stops a leaked or guessed
// session ID from revoking another user's session through
// Sulis.RevokeSession.
func (s *SessionStore) DeleteSession(_ context.Context, userID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[id]
	if !ok || sess.UserID != userID {
		return sulis.ErrSessionNotFound
	}
	delete(s.sessions, id)
	return nil
}

// DeleteUserSessions removes every session belonging to userID. Matching
// nothing is not an error.
func (s *SessionStore) DeleteUserSessions(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, sess := range s.sessions {
		if sess.UserID == userID {
			delete(s.sessions, id)
		}
	}
	return nil
}

// CleanExpired removes every session whose ExpiresAt is in the past.
func (s *SessionStore) CleanExpired(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
	return nil
}

// Len reports how many sessions are stored. It is not part of
// sulis.SessionStore; it exists so a test or an example can assert that a
// flow created no session at all, which is otherwise unobservable through the
// interface.
func (s *SessionStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.sessions)
}
