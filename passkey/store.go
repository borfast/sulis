package passkey

import (
	"context"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
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

	// Name is caller-supplied display metadata for this credential (e.g.
	// "YubiKey 5C", "Work laptop"). passkey never generates, infers, or
	// validates it — it starts empty and is only ever set through
	// Store.RenameCredential. A management UI should fall back to something
	// derived from CreatedAt/Transports when Name is empty.
	Name string

	// Transports lists the transports the client reported the authenticator
	// supports (e.g. "usb", "nfc", "ble", "hybrid", "internal") — the
	// registration response's "transports" field, populated from
	// waCredential.Transport in FinishRegistration. It reflects what the
	// client reported once, at registration time, and is not re-verified or
	// refreshed on subsequent logins.
	Transports []protocol.AuthenticatorTransport

	// BackupEligible reports whether the credential's authenticator is
	// capable of being backed up or synced across devices (the "BE" bit in
	// the authenticator data). Unlike Discoverable this is a verified
	// property, not merely client-reported: go-webauthn derives it from the
	// signed authenticator data on every ceremony and — critically —
	// re-checks it for consistency on every subsequent login. The value
	// persisted here must be fed back into every later ceremony's
	// credential list (see toWebAuthnCreds), or a genuinely backup-eligible
	// credential's next login is rejected with "Backup Eligible flag
	// inconsistency detected".
	BackupEligible bool

	// BackupState reports whether the credential is *currently* backed up
	// (the "BS" bit). Unlike BackupEligible this can change over a
	// credential's lifetime — e.g. a synced passkey moves in or out of a
	// device's keychain backup — so it is re-derived and re-persisted on
	// every successful login (see Store.UpdateCredentialAfterLogin), not
	// only set once at registration.
	BackupState bool

	// LastUsedAt records when this credential last completed a successful
	// login assertion — FinishLogin, FinishDiscoverableLogin, or their
	// []byte cores. It is nil until the credential's first
	// post-registration login: registering a credential does not count as
	// using it.
	LastUsedAt *time.Time

	// Discoverable records whether the authenticator created a client-side
	// discoverable ("resident key") credential — the kind
	// Service.BeginDiscoverableLogin's usernameless login needs in order to
	// find a credential without the caller supplying a username first.
	//
	// It is populated from the client's "credProps" extension output
	// (credProps.rk) on the registration response: true only when the
	// client explicitly reported rk == true, false otherwise (extension
	// absent, or credProps.rk == false). This is the only place
	// go-webauthn v0.17.4 surfaces a resident-key signal at all — the
	// finished credential's own Authenticator/Flags fields (UserPresent,
	// UserVerified, BackupEligible, BackupState) have no such bit, and
	// BackupEligible is a related but distinct property (can the
	// credential be synced/backed up, not whether it's discoverable
	// without a credential ID).
	//
	// LIMITATION: credProps is a client-reported (browser) extension
	// output, not part of the signed attestation object — it is not
	// cryptographically verified, and an older browser or authenticator
	// may omit it entirely even for a credential that is, in fact,
	// discoverable. Treat a false value as "not confirmed discoverable",
	// not as proof the credential isn't; this under-reports rather than
	// over-reports, so BeginDiscoverableLogin may simply fail to offer such
	// a credential rather than something being accepted that shouldn't be.
	Discoverable bool

	CreatedAt time.Time
}

// Store defines the persistence operations for passkey credentials.
type Store interface {
	SaveCredential(ctx context.Context, cred *Credential) error
	GetCredentialsByUserID(ctx context.Context, userID string) ([]Credential, error)
	GetCredentialByID(ctx context.Context, credentialID []byte) (*Credential, error)

	// UpdateCredentialAfterLogin persists the bookkeeping that must change
	// on every successful login assertion: SignCount (clone detection),
	// BackupState (can flip independently of BackupEligible — see
	// Credential.BackupState), and LastUsedAt. go-webauthn's own storage
	// guidance (the "Storage" section of the
	// github.com/go-webauthn/webauthn/webauthn package doc) says sign
	// count, clone-warning, and BackupState-when-BackupEligible MUST be
	// written back on every successful FinishLogin/ValidateLogin so the
	// next ceremony observes current values; bundling all three in one
	// store call keeps that invariant enforceable in one place, rather
	// than splitting it across calls a caller could apply out of order or
	// only partially. This replaces the narrower UpdateCredentialSignCount.
	UpdateCredentialAfterLogin(ctx context.Context, credentialID []byte, signCount uint32, backupState bool, lastUsedAt time.Time) error

	// DeleteCredential removes the credential identified by id (a
	// Credential.ID value — the store's own opaque ID, not the raw
	// WebAuthn Credential.CredentialID) if it belongs to userID.
	//
	// If id is userID's only remaining credential and allowLast is false,
	// the store MUST refuse the deletion and return ErrLastCredential
	// instead of removing it. The membership check, the remaining-count
	// check, and the removal itself MUST happen as a single atomic
	// operation with respect to any concurrent call for the same userID —
	// this is the same requirement ChallengeStore.ConsumeChallenge,
	// TokenStore.ConsumeToken, and recovery.Store.ConsumeCode already place
	// on their own check-and-mutate operations, for the same reason: a
	// separate read-then-write lets two concurrent callers each observe the
	// pre-mutation state before either mutation lands. Concretely, without
	// atomicity here, two goroutines each deleting one of a user's last two
	// credentials could both read count==2, both pass the guard with
	// allowLast==false, and both succeed — leaving the user with zero
	// credentials, exactly the lockout state this guard exists to prevent,
	// reached through the guarded path.
	//
	// Reference implementations: SQL — run the count check and the DELETE
	// inside one transaction after locking the user's credential rows
	// (SELECT ... FOR UPDATE), or express both in one statement, e.g.
	// "DELETE FROM credentials WHERE id = $1 AND user_id = $2 AND
	// ($3 OR (SELECT COUNT(*) FROM credentials WHERE user_id = $2) > 1)"
	// and check the affected-row count to distinguish "deleted" from
	// "refused" (also handling "id didn't exist" — see below). A
	// single-threaded or mutex-guarded in-memory store can simply perform
	// the check and the removal while holding the same lock.
	//
	// Returns ErrPasskeyNotFound if id does not name a credential owned by
	// userID.
	//
	// Service.DeleteCredential is a thin wrapper around this method: the
	// last-credential guard lives here, in the store, not in Service,
	// specifically so the check and the mutation cannot be split across
	// two separate calls the way a Service-level "load, check, then
	// delete" would split them.
	DeleteCredential(ctx context.Context, userID, id string, allowLast bool) error

	// DeleteCredentialsByUserID removes every credential owned by userID —
	// e.g. as part of deleting the user's whole account. It does not apply
	// the last-credential guard Service.DeleteCredential enforces:
	// deleting an entire account is a stronger action that the caller has
	// presumably already gated on its own, and silently leaving one
	// credential behind because it "happened to be last" would be
	// surprising here.
	DeleteCredentialsByUserID(ctx context.Context, userID string) error

	// RenameCredential sets Credential.Name — caller-supplied display
	// metadata that passkey itself never generates or validates. Returns
	// ErrPasskeyNotFound if id does not match a stored credential.
	RenameCredential(ctx context.Context, id, name string) error
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
