package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/borfast/sulis/passkey"

	"github.com/go-webauthn/webauthn/protocol"
)

// PasskeyStore is the PostgreSQL passkey.Store.
//
// DeleteCredential is where the danger lives, and it is the only method here
// that needs a transaction. Its guard asks how MANY credentials the user has,
// and that is the one question a snapshot answers wrongly under concurrency:
// two callers each deleting a different one of a user's last two credentials
// both count 2, both pass the allowLast == false guard, and both succeed — the
// exact lockout the guard exists to prevent, reached through the guarded path.
// Row locks do not help, because the two callers lock different rows. See
// DeleteCredential for what does.
type PasskeyStore struct {
	db *sql.DB
}

var _ passkey.Store = (*PasskeyStore)(nil)

// credentialColumns is the SELECT list every read below shares, in the order
// scanCredential reads them.
//
// #nosec G101 -- a list of column names, not a credential
const credentialColumns = `id, user_id, credential_id, public_key, attestation_type,
	aaguid, sign_count, name, transports, backup_eligible, backup_state,
	discoverable, last_used_at, created_at`

// SaveCredential persists cred, replacing any credential already stored under
// the same ID. Registration is the caller; the bookkeeping that changes on every
// later login goes through UpdateCredentialAfterLogin instead.
func (s *PasskeyStore) SaveCredential(ctx context.Context, cred *passkey.Credential) error {
	transports, err := marshalTransports(cred.Transports)
	if err != nil {
		return err
	}

	const q = `INSERT INTO passkey_credentials (` + credentialColumns + `)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (id) DO UPDATE SET
			user_id = excluded.user_id,
			credential_id = excluded.credential_id,
			public_key = excluded.public_key,
			attestation_type = excluded.attestation_type,
			aaguid = excluded.aaguid,
			sign_count = excluded.sign_count,
			name = excluded.name,
			transports = excluded.transports,
			backup_eligible = excluded.backup_eligible,
			backup_state = excluded.backup_state,
			discoverable = excluded.discoverable,
			last_used_at = excluded.last_used_at,
			created_at = excluded.created_at`
	_, err = s.db.ExecContext(ctx, q,
		cred.ID, cred.UserID, cred.CredentialID, cred.PublicKey, cred.AttestationType,
		nullableBytes(cred.AAGUID), int64(cred.SignCount), cred.Name, transports,
		cred.BackupEligible, cred.BackupState, cred.Discoverable,
		nullableTime(cred.LastUsedAt), formatTime(cred.CreatedAt),
	)
	if err != nil {
		return fmt.Errorf("sulis/postgres: saving a passkey credential: %w", err)
	}
	return nil
}

// GetCredentialsByUserID returns every credential owned by userID. A user with
// no credentials is not an error: it is how a caller learns the user has no
// passkey enrolled.
func (s *PasskeyStore) GetCredentialsByUserID(ctx context.Context, userID string) ([]passkey.Credential, error) {
	const q = `SELECT ` + credentialColumns + ` FROM passkey_credentials WHERE user_id = $1`

	rows, err := s.db.QueryContext(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("sulis/postgres: listing a user's passkey credentials: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var creds []passkey.Credential
	for rows.Next() {
		var cred passkey.Credential
		if err := scanCredential(rows, &cred); err != nil {
			return nil, err
		}
		creds = append(creds, cred)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sulis/postgres: listing a user's passkey credentials: %w", err)
	}
	return creds, nil
}

// GetCredentialByID returns the credential whose raw WebAuthn credential ID is
// credentialID, or passkey.ErrPasskeyNotFound.
func (s *PasskeyStore) GetCredentialByID(ctx context.Context, credentialID []byte) (*passkey.Credential, error) {
	const q = `SELECT ` + credentialColumns + ` FROM passkey_credentials WHERE credential_id = $1`

	var cred passkey.Credential
	if err := scanCredential(s.db.QueryRowContext(ctx, q, credentialID), &cred); err != nil {
		return nil, err
	}
	return &cred, nil
}

// UpdateCredentialAfterLogin persists the three fields that must change together
// after every successful assertion: SignCount (clone detection), BackupState
// (which can flip independently of BackupEligible), and LastUsedAt. go-webauthn
// re-reads all three on the next ceremony, so a store that persists only some of
// them breaks the credential's NEXT login rather than this one — which is why
// they are one statement and one method.
//
// Zero rows affected is passkey.ErrPasskeyNotFound.
func (s *PasskeyStore) UpdateCredentialAfterLogin(ctx context.Context, credentialID []byte, signCount uint32, backupState bool, lastUsedAt time.Time) error {
	const q = `UPDATE passkey_credentials
		SET sign_count = $1, backup_state = $2, last_used_at = $3
		WHERE credential_id = $4`

	res, err := s.db.ExecContext(ctx, q,
		int64(signCount), backupState, formatTime(lastUsedAt), credentialID)
	if err != nil {
		return fmt.Errorf("sulis/postgres: updating a passkey credential after login: %w", err)
	}
	n, err := affected(res, "updating a passkey credential after login")
	if err != nil {
		return err
	}
	if n == 0 {
		return passkey.ErrPasskeyNotFound
	}
	return nil
}

// DeleteCredential removes the credential identified by id if it belongs to
// userID, refusing to remove userID's last one unless allowLast is set:
//
//	DELETE FROM passkey_credentials
//	 WHERE id = $1 AND user_id = $2
//	   AND ($3 OR (SELECT COUNT(*) FROM passkey_credentials WHERE user_id = $2) > 1)
//
// One statement still carries the ownership check, the count check, and the
// removal — but on PostgreSQL that is not enough on its own, and this is the
// clearest example in the package of why. Two callers deleting DIFFERENT rows
// take different row locks, so neither blocks; each counts the user's
// credentials in its own snapshot, both see 2, both pass the guard, and the user
// ends with none. The transaction therefore opens by taking the user's advisory
// lock, which makes deletions for one user serial and leaves deletions for
// different users fully concurrent. The loser then counts 1 and is refused,
// which is the answer the guard exists to give.
//
// Zero rows affected means either that the guard refused or that (id, userID)
// names nothing, and those are different errors to the caller —
// passkey.ErrLastCredential versus passkey.ErrPasskeyNotFound — so a follow-up
// existence check inside the same transaction tells them apart.
func (s *PasskeyStore) DeleteCredential(ctx context.Context, userID, id string, allowLast bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sulis/postgres: deleting a passkey credential: %w", err)
	}
	defer rollback(tx)

	if err := lockUser(ctx, tx, advisoryClassPasskey, userID); err != nil {
		return err
	}

	const del = `DELETE FROM passkey_credentials
		WHERE id = $1 AND user_id = $2
		  AND ($3 OR (SELECT COUNT(*) FROM passkey_credentials WHERE user_id = $2) > 1)`

	res, err := tx.ExecContext(ctx, del, id, userID, allowLast)
	if err != nil {
		return fmt.Errorf("sulis/postgres: deleting a passkey credential: %w", err)
	}
	n, err := affected(res, "deleting a passkey credential")
	if err != nil {
		return err
	}
	if n == 0 {
		var exists int
		err := tx.QueryRowContext(ctx,
			`SELECT 1 FROM passkey_credentials WHERE id = $1 AND user_id = $2`, id, userID,
		).Scan(&exists)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return passkey.ErrPasskeyNotFound
		case err != nil:
			return fmt.Errorf("sulis/postgres: deleting a passkey credential: %w", err)
		default:
			return passkey.ErrLastCredential
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sulis/postgres: committing a passkey credential deletion: %w", err)
	}
	return nil
}

// DeleteCredentialsByUserID removes every credential owned by userID, with no
// last-credential guard: deleting a whole account is a stronger action the
// caller has already gated, and leaving one credential behind because it
// happened to be last would be surprising here.
func (s *PasskeyStore) DeleteCredentialsByUserID(ctx context.Context, userID string) error {
	const q = `DELETE FROM passkey_credentials WHERE user_id = $1`

	if _, err := s.db.ExecContext(ctx, q, userID); err != nil {
		return fmt.Errorf("sulis/postgres: deleting a user's passkey credentials: %w", err)
	}
	return nil
}

// RenameCredential sets a credential's display name — caller-supplied metadata
// passkey itself never generates or validates. Zero rows affected is
// passkey.ErrPasskeyNotFound.
func (s *PasskeyStore) RenameCredential(ctx context.Context, id, name string) error {
	const q = `UPDATE passkey_credentials SET name = $1 WHERE id = $2`

	res, err := s.db.ExecContext(ctx, q, name, id)
	if err != nil {
		return fmt.Errorf("sulis/postgres: renaming a passkey credential: %w", err)
	}
	n, err := affected(res, "renaming a passkey credential")
	if err != nil {
		return err
	}
	if n == 0 {
		return passkey.ErrPasskeyNotFound
	}
	return nil
}

// ChallengeStore is the PostgreSQL passkey.ChallengeStore.
//
// ConsumeChallenge is one DELETE ... RETURNING, so two concurrent finishes of
// the same ceremony cannot both receive the challenge — a replayed WebAuthn
// response must not be verifiable twice against one challenge. The second
// deleter blocks on the first's row lock and then finds nothing to return.
type ChallengeStore struct {
	db *sql.DB

	// TTL is how long a saved challenge stays consumable. Zero — or any
	// non-positive value, since "expire before you were saved" is not a
	// coherent request — means DefaultChallengeTTL. The interface asks
	// implementations to expire entries after roughly the lifetime of a
	// WebAuthn ceremony; nothing above the store enforces that, so it is
	// enforced here.
	TTL time.Duration
}

var _ passkey.ChallengeStore = (*ChallengeStore)(nil)

// DefaultChallengeTTL is how long a challenge stays consumable when
// ChallengeStore.TTL is left at zero, matching the lifetime of a WebAuthn
// ceremony.
const DefaultChallengeTTL = 5 * time.Minute

// ErrChallengeNotFound is returned by ChallengeStore.ConsumeChallenge when no
// live challenge is stored under the key — already consumed, expired, or never
// saved. passkey.ChallengeStore leaves this error implementation-defined; the
// caller normalizes whatever comes back to passkey.ErrChallengeExpired.
var ErrChallengeNotFound = errors.New("sulis/postgres: challenge not found")

// SaveChallenge stores sessionData under key, replacing anything already there.
// The bytes are copied into the database, so a caller reusing its buffer
// afterwards cannot rewrite a challenge it already handed over.
func (s *ChallengeStore) SaveChallenge(ctx context.Context, key string, sessionData []byte) error {
	const q = `INSERT INTO passkey_challenges (challenge_key, session_data, created_at, expires_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (challenge_key) DO UPDATE SET
			session_data = excluded.session_data,
			created_at = excluded.created_at,
			expires_at = excluded.expires_at`

	now := time.Now()
	_, err := s.db.ExecContext(ctx, q, key, sessionData,
		formatTime(now), formatTime(now.Add(s.ttl())))
	if err != nil {
		return fmt.Errorf("sulis/postgres: saving a passkey challenge: %w", err)
	}
	return nil
}

// ConsumeChallenge fetches and deletes the challenge stored under key in one
// statement, so only one caller can ever receive it.
//
// An expired challenge is deleted and then refused, rather than filtered out of
// the DELETE: burning the row either way matches the "failures burn the token"
// direction the rest of this module takes, and leaves nothing behind for a
// second attempt to find.
func (s *ChallengeStore) ConsumeChallenge(ctx context.Context, key string) ([]byte, error) {
	const q = `DELETE FROM passkey_challenges WHERE challenge_key = $1
		RETURNING session_data, expires_at`

	var (
		data      []byte
		expiresAt string
	)
	err := s.db.QueryRowContext(ctx, q, key).Scan(&data, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrChallengeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sulis/postgres: consuming a passkey challenge: %w", err)
	}

	expiry, err := parseTime(expiresAt)
	if err != nil {
		return nil, err
	}
	if !time.Now().Before(expiry) {
		return nil, ErrChallengeNotFound
	}
	return data, nil
}

// DeleteExpiredChallenges removes challenges nobody finished in time. The
// ChallengeStore interface has no sweep method — ConsumeChallenge already
// removes the row it reads, and an abandoned ceremony is the only way one is
// ever left behind — so this is offered for a caller that wants to run it on a
// timer rather than required by the contract.
func (s *ChallengeStore) DeleteExpiredChallenges(ctx context.Context) error {
	const q = `DELETE FROM passkey_challenges WHERE expires_at < $1`

	if _, err := s.db.ExecContext(ctx, q, formatTime(time.Now())); err != nil {
		return fmt.Errorf("sulis/postgres: deleting expired passkey challenges: %w", err)
	}
	return nil
}

// ttl reports the configured challenge lifetime, or the default.
func (s *ChallengeStore) ttl() time.Duration {
	if s.TTL > 0 {
		return s.TTL
	}
	return DefaultChallengeTTL
}

// scanCredential reads one row into dst, reporting a missing row as
// passkey.ErrPasskeyNotFound.
func scanCredential(row scanner, dst *passkey.Credential) error {
	var (
		aaguid     []byte
		signCount  int64
		transports sql.NullString
		lastUsedAt sql.NullString
		createdAt  string
	)
	err := row.Scan(
		&dst.ID, &dst.UserID, &dst.CredentialID, &dst.PublicKey, &dst.AttestationType,
		&aaguid, &signCount, &dst.Name, &transports, &dst.BackupEligible,
		&dst.BackupState, &dst.Discoverable, &lastUsedAt, &createdAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return passkey.ErrPasskeyNotFound
	}
	if err != nil {
		return fmt.Errorf("sulis/postgres: reading a passkey credential: %w", err)
	}

	if err := unmarshalJSON(transports, &dst.Transports); err != nil {
		return err
	}
	if dst.LastUsedAt, err = scanNullableTime(lastUsedAt); err != nil {
		return err
	}
	if dst.CreatedAt, err = parseTime(createdAt); err != nil {
		return err
	}
	dst.AAGUID = aaguid
	dst.SignCount = uint32(signCount) // #nosec G115 -- the column is only ever written from a uint32 sign count
	return nil
}

// marshalTransports renders the transports list for storage, mapping an empty
// list to SQL NULL so an absent list reads back as nil rather than as an empty
// slice the caller never provided.
func marshalTransports(transports []protocol.AuthenticatorTransport) (any, error) {
	if len(transports) == 0 {
		return nil, nil
	}
	return marshalJSON(transports)
}

// nullableBytes maps an empty byte slice to SQL NULL, so a column that was never
// populated reads back as nil.
func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
