package memstore

import (
	"context"
	"maps"
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

	s.sessions[session.ID] = cloneSession(session)
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
			return cloneSession(sess), nil
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

// DeleteUserSessionsExcept removes every session belonging to userID except
// the one identified by keepSessionID. keepSessionID naming a session that
// doesn't exist, or one belonging to someone else, is not an error — every
// other session for userID is removed regardless. See
// sulis.SessionStore.DeleteUserSessionsExcept's doc comment.
func (s *SessionStore) DeleteUserSessionsExcept(_ context.Context, userID, keepSessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, sess := range s.sessions {
		if sess.UserID == userID && id != keepSessionID {
			delete(s.sessions, id)
		}
	}
	return nil
}

// ListUserSessions returns a copy of every session belonging to userID.
// Matching nothing is not an error — a nil slice and a nil error.
func (s *SessionStore) ListUserSessions(_ context.Context, userID string) ([]sulis.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []sulis.Session
	for _, sess := range s.sessions {
		if sess.UserID == userID {
			out = append(out, *cloneSession(sess))
		}
	}
	return out, nil
}

// UpdateAuthenticatedAt stamps the session identified by id with at, leaving
// every other field untouched, and returns sulis.ErrSessionNotFound if id
// does not exist. This is the write path behind sulis.Sulis.ReAuthenticate.
func (s *SessionStore) UpdateAuthenticatedAt(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[id]
	if !ok {
		return sulis.ErrSessionNotFound
	}
	sess.AuthenticatedAt = at
	return nil
}

// TouchSession stamps the session identified by id with a fresh lastSeen and
// idleExpires, leaving every other field untouched, and returns
// sulis.ErrSessionNotFound if id does not exist. A nil idleExpires clears
// any previously-stored deadline. This is the write path behind
// sulis.Sulis.ValidateSession's throttled liveness touch.
func (s *SessionStore) TouchSession(_ context.Context, id string, lastSeen time.Time, idleExpires *time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[id]
	if !ok {
		return sulis.ErrSessionNotFound
	}
	sess.LastSeenAt = lastSeen
	if idleExpires == nil {
		sess.IdleExpiresAt = nil
	} else {
		deadline := *idleExpires
		sess.IdleExpiresAt = &deadline
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

// cloneSession copies a session deeply enough that nothing mutable is shared
// across the store boundary in either direction. Metadata is a map, so a plain
// struct copy would leave the caller holding a live handle on the stored
// session — and a session a caller can rewrite outside CreateSession is a
// session whose owner a caller can rewrite.
//
// The map is cloned one level deep; values inside it are copied as-is. See
// cloneUser for why that line is drawn there.
func cloneSession(sess *sulis.Session) *sulis.Session {
	cp := *sess
	if sess.Metadata != nil {
		cp.Metadata = maps.Clone(sess.Metadata)
	}
	if sess.IdleExpiresAt != nil {
		deadline := *sess.IdleExpiresAt
		cp.IdleExpiresAt = &deadline
	}
	return &cp
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
