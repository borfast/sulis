package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/borfast/sulis"
)

// TokenStore is an in-memory sulis.TokenStore.
type TokenStore struct {
	mu     sync.Mutex
	tokens map[string]*sulis.Token
}

var _ sulis.TokenStore = (*TokenStore)(nil)

// NewTokenStore returns an empty TokenStore.
func NewTokenStore() *TokenStore {
	return &TokenStore{tokens: make(map[string]*sulis.Token)}
}

// CreateToken stores a copy of token, keyed by its ID.
func (s *TokenStore) CreateToken(_ context.Context, token *sulis.Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cp := *token
	s.tokens[token.ID] = &cp
	return nil
}

// ConsumeToken implements the atomic find-and-mark documented on
// sulis.TokenStore.ConsumeToken: the lookup, the Used check, and the write
// all happen while holding s.mu, so of any number of concurrent callers
// presenting the same token exactly one is handed it and the rest see
// ErrTokenAlreadyUsed. A SQL store replaces this lock with a single
// conditional statement (UPDATE ... WHERE hash = ? AND purpose = ? AND used =
// false) and distinguishes "no match" from "already used" by re-reading the
// row when zero rows are affected.
func (s *TokenStore) ConsumeToken(_ context.Context, hash string, purpose sulis.TokenPurpose) (*sulis.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, t := range s.tokens {
		if t.TokenHash != hash || t.Purpose != purpose {
			continue
		}
		if t.Used {
			return nil, sulis.ErrTokenAlreadyUsed
		}
		t.Used = true
		cp := *t
		return &cp, nil
	}
	return nil, sulis.ErrTokenNotFound
}

// DeleteExpiredTokens removes every token whose ExpiresAt is in the past.
func (s *TokenStore) DeleteExpiredTokens(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, t := range s.tokens {
		if now.After(t.ExpiresAt) {
			delete(s.tokens, id)
		}
	}
	return nil
}

// DeleteUserTokens removes every token belonging to userID with the given
// purpose. Matching nothing is not an error.
func (s *TokenStore) DeleteUserTokens(_ context.Context, userID string, purpose sulis.TokenPurpose) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, t := range s.tokens {
		if t.UserID == userID && t.Purpose == purpose {
			delete(s.tokens, id)
		}
	}
	return nil
}
