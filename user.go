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
}

// UserStore defines the persistence operations for users.
// Consumers implement this interface for their own database.
type UserStore interface {
	CreateUser(ctx context.Context, user *User) error
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id string) error
}
