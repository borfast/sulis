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
	// DisabledAt records when DisableUser took the account out of service.
	// Nil means the account is active. VerifyPassword's post-verification
	// check, completeFirstFactor, issueSessionForUser, and CompleteTwoFactor
	// all reject with ErrAccountDisabled while it is set, and ValidateSession
	// rejects an already-issued session the same way — so disabling an
	// account invalidates every session already issued, not merely future
	// logins. Cleared only by EnableUser.
	DisabledAt *time.Time
	// DisabledReason is caller-supplied context recorded by DisableUser
	// (e.g. "reported for abuse", "closed by support"). sulis never inspects
	// it. EnableUser clears it back to empty alongside DisabledAt.
	DisabledReason string
	// LockedUntil records the end of a temporary authentication lockout.
	// Nil, or a time already in the past, means the account authenticates
	// normally. It is set only by the optional automatic-lockout mechanism
	// (see WithFailureLockout) after repeated wrong passwords; the same
	// post-verification checks that reject ErrAccountDisabled also reject
	// ErrAccountLocked while this is still in the future. It is cleared
	// (along with FailedLoginAttempts) the next time a correct password
	// verifies outside the window, or the account's password is
	// successfully changed or reset (ChangePassword, ResetPassword,
	// SetInitialPassword) — there is no explicit unlock call for either.
	// Unlike DisabledAt, an active lock does not invalidate sessions already
	// issued: ValidateSession does not check it, only new authentication
	// does (see the README's "Account disable and lockout" section for why);
	// and unlike DisabledAt, a password reset/change DOES clear it — proving
	// control of the account well enough to set a new password is at least
	// as strong an identity proof as the login password itself, whereas
	// DisabledAt records an operator's decision that no proof of the
	// password reverses.
	LockedUntil *time.Time
	// FailedLoginAttempts counts consecutive wrong passwords since the last
	// correct one. It only ever advances when WithFailureLockout is
	// configured, and is reset to 0 whenever a correct password verifies
	// outside an active lockout window, or the account's password is
	// successfully changed or reset.
	FailedLoginAttempts int
	// Version guards against lost updates. It is set by the store on read and
	// must be passed back unchanged in UpdateUser, which applies the write
	// only if it still matches the persisted row. Callers outside the store
	// never set it themselves.
	Version uint64
}

// UserStore defines the persistence operations for users.
// Consumers implement this interface for their own database.
//
// A store MUST NOT share mutable state with its callers in either direction.
// Metadata is a map and EmailVerifiedAt, DisabledAt, and LockedUntil are each
// a pointer, so copying a *User with a plain struct assignment copies a map
// header and an address, not the map and not the time — leaving the caller
// holding a live handle on the stored row. That is a way to rewrite a
// persisted user without going through UpdateUser at all, which defeats the
// Version precondition below by simply stepping around it. Copy the map (one
// level is enough; values inside it are the caller's business) and each
// pointed-to time when storing a user and when returning one. Stores that
// reconstruct rows from a database read get this for free; in-memory ones do
// not. storetest.RunUserStore checks it.
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
