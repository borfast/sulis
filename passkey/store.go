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
// Keys are opaque strings scoped by ceremony (e.g. "register:<userID>",
// "login:<ceremonyID>", or "discover:<ceremonyID>"), not bare user IDs, so
// that concurrent ceremonies for the same user cannot clobber each other's
// saved challenge. Implementations should expire entries after roughly 5
// minutes, matching the lifetime of a WebAuthn ceremony.
type ChallengeStore interface {
	SaveChallenge(ctx context.Context, key string, sessionData []byte) error

	// ConsumeChallenge atomically fetches and deletes the challenge data
	// stored under key in a single operation, so that only one caller can
	// ever receive a given challenge: two concurrent finishes of the same
	// ceremony must not both succeed in retrieving it. Reference
	// implementations: Redis GETDEL, or SQL "DELETE ... RETURNING" (or an
	// equivalent SELECT ... FOR UPDATE followed by DELETE inside a single
	// transaction).
	//
	// Returns an implementation-defined not-found error if no challenge is
	// stored under key (already consumed, expired, or never saved); the
	// caller normalizes any error from this method to ErrChallengeExpired.
	ConsumeChallenge(ctx context.Context, key string) ([]byte, error)
}
