package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/borfast/sulis/passkey"

	"github.com/go-webauthn/webauthn/protocol"
)

// PasskeyStore is the SQLite passkey.Store.
//
// DeleteCredential is where the danger lives, and it is the only method here
// that needs more than one statement. The membership check, the
// remaining-count check, and the removal are expressed as a single DELETE
// whose WHERE clause carries all three; the follow-up query exists only to
// tell the two zero-row outcomes apart for the caller, and runs inside the
// same transaction. Split the guard from the delete and two goroutines each
// removing one of a user's last two credentials both observe count == 2, both
// pass the allowLast == false guard, and both succeed — the exact lockout the
// guard exists to prevent, reached through the guarded path.
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
// the same ID. Registration is the caller; the bookkeeping that changes on
// every later login goes through UpdateCredentialAfterLogin instead.
func (s *PasskeyStore) SaveCredential(ctx context.Context, cred *passkey.Credential) error {
	transports, err := marshalTransports(cred.Transports)
	if err != nil {
		return err
	}

	const q = `INSERT INTO passkey_credentials (` + credentialColumns + `)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
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
		boolToInt(cred.BackupEligible), boolToInt(cred.BackupState),
		boolToInt(cred.Discoverable), nullableTime(cred.LastUsedAt),
		formatTime(cred.CreatedAt),
	)
	if err != nil {
		return fmt.Errorf("sulis/sqlite: saving a passkey credential: %w", err)
	}
	return nil
}

// GetCredentialsByUserID returns every credential owned by userID. A user
// with no credentials is not an error: it is how a caller learns the user has
// no passkey enrolled.
func (s *PasskeyStore) GetCredentialsByUserID(ctx context.Context, userID string) ([]passkey.Credential, error) {
	const q = `SELECT ` + credentialColumns + ` FROM passkey_credentials WHERE user_id = ?`

	rows, err := s.db.QueryContext(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("sulis/sqlite: listing a user's passkey credentials: %w", err)
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
		return nil, fmt.Errorf("sulis/sqlite: listing a user's passkey credentials: %w", err)
	}
	return creds, nil
}

// GetCredentialByID returns the credential whose raw WebAuthn credential ID
// is credentialID, or passkey.ErrPasskeyNotFound.
func (s *PasskeyStore) GetCredentialByID(ctx context.Context, credentialID []byte) (*passkey.Credential, error) {
	const q = `SELECT ` + credentialColumns + ` FROM passkey_credentials WHERE credential_id = ?`

	var cred passkey.Credential
	if err := scanCredential(s.db.QueryRowContext(ctx, q, credentialID), &cred); err != nil {
		return nil, err
	}
	return &cred, nil
}

// UpdateCredentialAfterLogin persists the three fields that must change
// together after every successful assertion: SignCount (clone detection),
// BackupState (which can flip independently of BackupEligible), and
// LastUsedAt. go-webauthn re-reads all three on the next ceremony, so a store
// that persists only some of them breaks the credential's NEXT login rather
// than this one — which is why they are one statement and one method.
//
// Zero rows affected is passkey.ErrPasskeyNotFound.
func (s *PasskeyStore) UpdateCredentialAfterLogin(ctx context.Context, credentialID []byte, signCount uint32, backupState bool, lastUsedAt time.Time) error {
	const q = `UPDATE passkey_credentials
		SET sign_count = ?, backup_state = ?, last_used_at = ?
		WHERE credential_id = ?`

	res, err := s.db.ExecContext(ctx, q,
		int64(signCount), boolToInt(backupState), formatTime(lastUsedAt), credentialID)
	if err != nil {
		return fmt.Errorf("sulis/sqlite: updating a passkey credential after login: %w", err)
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
//	 WHERE id = ? AND user_id = ?
//	   AND (? = 1 OR (SELECT COUNT(*) FROM passkey_credentials WHERE user_id = ?) > 1)
//
// One statement carries the ownership check, the count check, and the
// removal, so no concurrent caller can slip between them. Zero rows affected
// means either that the guard refused or that (id, userID) names nothing, and
// those are different errors to the caller — passkey.ErrLastCredential versus
// passkey.ErrPasskeyNotFound — so a follow-up existence check inside the same
// transaction tells them apart.
func (s *PasskeyStore) DeleteCredential(ctx context.Context, userID, id string, allowLast bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sulis/sqlite: deleting a passkey credential: %w", err)
	}
	defer rollback(tx)

	const del = `DELETE FROM passkey_credentials
		WHERE id = ? AND user_id = ?
		  AND (? = 1 OR (SELECT COUNT(*) FROM passkey_credentials WHERE user_id = ?) > 1)`

	res, err := tx.ExecContext(ctx, del, id, userID, boolToInt(allowLast), userID)
	if err != nil {
		return fmt.Errorf("sulis/sqlite: deleting a passkey credential: %w", err)
	}
	n, err := affected(res, "deleting a passkey credential")
	if err != nil {
		return err
	}
	if n == 0 {
		var exists int
		err := tx.QueryRowContext(ctx,
			`SELECT 1 FROM passkey_credentials WHERE id = ? AND user_id = ?`, id, userID,
		).Scan(&exists)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return passkey.ErrPasskeyNotFound
		case err != nil:
			return fmt.Errorf("sulis/sqlite: deleting a passkey credential: %w", err)
		default:
			return passkey.ErrLastCredential
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sulis/sqlite: committing a passkey credential deletion: %w", err)
	}
	return nil
}

// DeleteCredentialsByUserID removes every credential owned by userID, with no
// last-credential guard: deleting a whole account is a stronger action the
// caller has already gated, and leaving one credential behind because it
// happened to be last would be surprising here.
func (s *PasskeyStore) DeleteCredentialsByUserID(ctx context.Context, userID string) error {
	const q = `DELETE FROM passkey_credentials WHERE user_id = ?`

	if _, err := s.db.ExecContext(ctx, q, userID); err != nil {
		return fmt.Errorf("sulis/sqlite: deleting a user's passkey credentials: %w", err)
	}
	return nil
}

// RenameCredential sets a credential's display name — caller-supplied
// metadata passkey itself never generates or validates. Zero rows affected is
// passkey.ErrPasskeyNotFound.
func (s *PasskeyStore) RenameCredential(ctx context.Context, id, name string) error {
	const q = `UPDATE passkey_credentials SET name = ? WHERE id = ?`

	res, err := s.db.ExecContext(ctx, q, name, id)
	if err != nil {
		return fmt.Errorf("sulis/sqlite: renaming a passkey credential: %w", err)
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

// ChallengeStore is the SQLite passkey.ChallengeStore.
//
// ConsumeChallenge is one DELETE ... RETURNING, so two concurrent finishes of
// the same ceremony cannot both receive the challenge — a replayed WebAuthn
// response must not be verifiable twice against one challenge.
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
// live challenge is stored under the key — already consumed, expired, or
// never saved. passkey.ChallengeStore leaves this error
// implementation-defined; the caller normalizes whatever comes back to
// passkey.ErrChallengeExpired.
var ErrChallengeNotFound = errors.New("sulis/sqlite: challenge not found")

// SaveChallenge stores sessionData under key, replacing anything already
// there. The bytes are copied into the database, so a caller reusing its
// buffer afterwards cannot rewrite a challenge it already handed over.
func (s *ChallengeStore) SaveChallenge(ctx context.Context, key string, sessionData []byte) error {
	const q = `INSERT INTO passkey_challenges (challenge_key, session_data, created_at, expires_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(challenge_key) DO UPDATE SET
			session_data = excluded.session_data,
			created_at = excluded.created_at,
			expires_at = excluded.expires_at`

	now := time.Now()
	_, err := s.db.ExecContext(ctx, q, key, sessionData,
		formatTime(now), formatTime(now.Add(s.ttl())))
	if err != nil {
		return fmt.Errorf("sulis/sqlite: saving a passkey challenge: %w", err)
	}
	return nil
}

// ConsumeChallenge fetches and deletes the challenge stored under key in one
// statement, so only one caller can ever receive it.
//
// An expired challenge is deleted and then refused, rather than filtered out
// of the DELETE: burning the row either way matches the "failures burn the
// token" direction the rest of this module takes, and leaves nothing behind
// for a second attempt to find.
func (s *ChallengeStore) ConsumeChallenge(ctx context.Context, key string) ([]byte, error) {
	const q = `DELETE FROM passkey_challenges WHERE challenge_key = ?
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
		return nil, fmt.Errorf("sulis/sqlite: consuming a passkey challenge: %w", err)
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
// ever left behind — so this is offered for a caller that wants to run it on
// a timer rather than required by the contract.
func (s *ChallengeStore) DeleteExpiredChallenges(ctx context.Context) error {
	const q = `DELETE FROM passkey_challenges WHERE expires_at < ?`

	if _, err := s.db.ExecContext(ctx, q, formatTime(time.Now())); err != nil {
		return fmt.Errorf("sulis/sqlite: deleting expired passkey challenges: %w", err)
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
		aaguid                                    []byte
		signCount                                 int64
		transports                                sql.NullString
		backupEligible, backupState, discoverable int64
		lastUsedAt                                sql.NullString
		createdAt                                 string
	)
	err := row.Scan(
		&dst.ID, &dst.UserID, &dst.CredentialID, &dst.PublicKey, &dst.AttestationType,
		&aaguid, &signCount, &dst.Name, &transports, &backupEligible, &backupState,
		&discoverable, &lastUsedAt, &createdAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return passkey.ErrPasskeyNotFound
	}
	if err != nil {
		return fmt.Errorf("sulis/sqlite: reading a passkey credential: %w", err)
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
	dst.BackupEligible = backupEligible != 0
	dst.BackupState = backupState != 0
	dst.Discoverable = discoverable != 0
	return nil
}

// marshalTransports renders the transports list for storage, mapping an empty
// list to SQL NULL so an absent list reads back as nil rather than as an
// empty slice the caller never provided.
func marshalTransports(transports []protocol.AuthenticatorTransport) (any, error) {
	if len(transports) == 0 {
		return nil, nil
	}
	return marshalJSON(transports)
}

// nullableBytes maps an empty byte slice to SQL NULL, so a column that was
// never populated reads back as nil.
func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
