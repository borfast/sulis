package memstore

import (
	"context"
	"sync"

	"github.com/borfast/sulis"
)

// UserStore is an in-memory sulis.UserStore.
//
// It enforces both of the requirements the interface places on a real
// implementation: e-mail uniqueness on every write path, and optimistic
// concurrency through sulis.User.Version. A SQL store gets the first from a
// UNIQUE index on the normalized e-mail column and the second from
// "UPDATE ... WHERE id = $1 AND version = $2"; a map needs the enclosing
// mutex to stand in for both, which is why every method here takes it.
type UserStore struct {
	mu    sync.Mutex
	users map[string]*sulis.User
}

var _ sulis.UserStore = (*UserStore)(nil)

// NewUserStore returns an empty UserStore.
func NewUserStore() *UserStore {
	return &UserStore{users: make(map[string]*sulis.User)}
}

// CreateUser stores a copy of user, rejecting an e-mail address another user
// already holds with sulis.ErrUserAlreadyExists. The check and the write
// happen under one lock, so of any number of concurrent creates for the same
// address exactly one lands — the guarantee a UNIQUE index gives a SQL store
// and that no caller-side pre-check can give.
//
// A duplicate ID is rejected the same way: two users cannot share a primary
// key, and silently overwriting one would lose an account.
func (s *UserStore) CreateUser(_ context.Context, user *sulis.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[user.ID]; exists {
		return sulis.ErrUserAlreadyExists
	}
	if s.emailTakenLocked(user.Email, user.ID) {
		return sulis.ErrUserAlreadyExists
	}

	cp := *user
	s.users[user.ID] = &cp
	return nil
}

// GetUserByID returns a copy of the stored user, or sulis.ErrUserNotFound.
func (s *UserStore) GetUserByID(_ context.Context, id string) (*sulis.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[id]
	if !ok {
		return nil, sulis.ErrUserNotFound
	}
	cp := *u
	return &cp, nil
}

// GetUserByEmail returns a copy of the user whose live e-mail address is
// email, or sulis.ErrUserNotFound. The address is compared exactly: sulis
// normalizes before it ever reaches a store, so a store that lowercased again
// here would only hide a caller passing an unnormalized address.
func (s *UserStore) GetUserByEmail(_ context.Context, email string) (*sulis.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.users {
		if u.Email == email {
			cp := *u
			return &cp, nil
		}
	}
	return nil, sulis.ErrUserNotFound
}

// UpdateUser applies user only while the stored row's Version still matches
// the one the caller read, returning sulis.ErrConcurrentUpdate otherwise and
// discarding the write, and rejects an e-mail address another user holds with
// sulis.ErrUserAlreadyExists. On success the stored Version advances by one.
//
// Both checks and the write are one critical section. Splitting them is the
// bug the contract exists to rule out: two flows that each read-modify-write
// the whole row would otherwise clobber each other, and the dangerous
// direction restores a password hash the user just rotated away from.
func (s *UserStore) UpdateUser(_ context.Context, user *sulis.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.users[user.ID]
	if !ok {
		return sulis.ErrUserNotFound
	}
	if existing.Version != user.Version {
		return sulis.ErrConcurrentUpdate
	}
	if s.emailTakenLocked(user.Email, user.ID) {
		return sulis.ErrUserAlreadyExists
	}

	cp := *user
	cp.Version = existing.Version + 1
	s.users[user.ID] = &cp
	return nil
}

// DeleteUser removes the user with the given ID. Deleting a user who is not
// there is not an error: the caller's intent is already satisfied.
func (s *UserStore) DeleteUser(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.users, id)
	return nil
}

// emailTakenLocked reports whether a user other than exceptID holds email.
// Callers must hold s.mu. exceptID excludes the row being written, so an
// update that changes anything but the address is not rejected as a
// collision with itself.
func (s *UserStore) emailTakenLocked(email, exceptID string) bool {
	for id, u := range s.users {
		if id != exceptID && u.Email == email {
			return true
		}
	}
	return false
}
