package passkey

import (
	"context"
	"time"
)

// Credential represents a registered WebAuthn/passkey credential.
type Credential struct {
	ID              string
	UserID          string
	CredentialID    []byte
	PublicKey       []byte
	AttestationType string
	AAGUID          []byte
	SignCount       uint32
	CreatedAt       time.Time
}

// Store defines the persistence operations for passkey credentials.
type Store interface {
	SaveCredential(ctx context.Context, cred *Credential) error
	GetCredentialsByUserID(ctx context.Context, userID string) ([]Credential, error)
	GetCredentialByID(ctx context.Context, credentialID []byte) (*Credential, error)
	UpdateCredentialSignCount(ctx context.Context, credentialID []byte, signCount uint32) error
	DeleteCredential(ctx context.Context, id string) error
}

// ChallengeStore handles the transient WebAuthn challenge/session data
// needed between the begin and finish steps of registration/authentication.
//
// Keys are opaque strings scoped by ceremony (e.g. "register:<userID>" or
// "login:<userID>"), not bare user IDs, so that concurrent registration and
// login ceremonies for the same user cannot clobber each other's saved
// challenge. Implementations should expire entries after roughly 5 minutes,
// matching the lifetime of a WebAuthn ceremony.
type ChallengeStore interface {
	SaveChallenge(ctx context.Context, key string, sessionData []byte) error
	GetChallenge(ctx context.Context, key string) ([]byte, error)
	DeleteChallenge(ctx context.Context, key string) error
}
