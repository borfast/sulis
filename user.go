package sulis

import (
	"context"
	"time"
)

// User represents an authenticated user.
type User struct {
	ID           string
	Email        string
	PasswordHash string // empty for passwordless-only users
	CreatedAt    time.Time
	UpdatedAt    time.Time
	Metadata     map[string]any
	// EmailVerifiedAt records when the user's email address was confirmed as
	// reachable (e.g. via VerifyEmail or a redeemed magic link). Nil means
	// the address has not been verified.
	EmailVerifiedAt *time.Time
	// PendingEmail holds a staged address awaiting proof of control, set by
	// ChangeEmail. The live Email field never changes except through a
	// successful ConfirmEmailChange, which also clears this back to empty.
	PendingEmail string
	// Version guards against lost updates. It is set by the store on read and
	// must be passed back unchanged in UpdateUser, which applies the write
	// only if it still matches the persisted row. Callers outside the store
	// never set it themselves.
	Version uint64
}

// UserStore defines the persistence operations for users.
// Consumers implement this interface for their own database.
//
// Email uniqueness MUST be enforced at the storage layer — e.g. a SQL UNIQUE
// index on the normalized email column — and CreateUser and UpdateUser MUST
// return ErrUserAlreadyExists when a write would violate it. This is not
// optional. Version (below) only guards a lost update on a single row; it
// says nothing about two different rows racing to claim the same address
// (e.g. two accounts both confirming a staged change to the same address).
// Nothing above this interface can make those two writes atomic with respect
// to each other, since by the time either call reaches UserStore they are
// independent reads and writes on different rows. A caller may re-check
// uniqueness with GetUserByEmail before writing (ConfirmEmailChange does),
// but that is only a best-effort early rejection, not the guarantee: two
// callers can both pass that check for the same address before either write
// lands. The store's write path enforcing the constraint is what actually
// closes the race.
type UserStore interface {
	// CreateUser persists a new user. Returns ErrUserAlreadyExists if user.Email
	// is already the live address of another user.
	CreateUser(ctx context.Context, user *User) error
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	// UpdateUser persists user, but ONLY if the stored row's version still
	// equals user.Version. On success the stored version MUST be incremented;
	// on mismatch the write MUST be discarded and ErrConcurrentUpdate
	// returned. Without this, two flows that each read-modify-write the whole
	// row can clobber each other — and the dangerous direction restores a
	// password hash the user just rotated away from.
	//
	//	UPDATE users SET ..., version = version + 1
	//	 WHERE id = $1 AND version = $2
	//
	// Zero rows affected means another writer won: return ErrConcurrentUpdate.
	//
	// UpdateUser MUST also return ErrUserAlreadyExists if user.Email would
	// collide with a different user's live email — e.g. two accounts racing
	// to confirm a change to the same staged address. This is the real
	// guarantee behind that race, not the in-library pre-check described
	// above.
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id string) error
}
