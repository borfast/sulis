-- Schema for the SQLite reference stores in this package.
--
-- Every constraint here exists because a store interface in sulis documents
-- behavior a Go implementation cannot be trusted to remember: the UNIQUE
-- index on users.email is what actually closes the two-accounts-claiming-one-
-- address race (UserStore's doc comment says so in as many words), the
-- version column is what makes UpdateUser's compare-and-swap expressible as
-- one statement, and the separate totp_active/totp_pending tables are what
-- stop a racing enrollment from replacing a working second factor.
--
-- Applied by Migrate, which runs the whole file in one transaction. It is
-- also exported as sqlite.Schema so an adopter can feed it to their own
-- migration tool instead.
--
-- # Types
--
-- Every table is STRICT, so a column declared TEXT rejects an integer rather
-- than silently storing one. Timestamps are TEXT in a fixed-width UTC layout
-- ("2006-01-02T15:04:05.000000000Z"): fixed width means lexicographic order
-- is chronological order, which is what the expiry sweeps below compare on,
-- and nine fractional digits round-trip a time.Time without losing
-- precision. Booleans are INTEGER 0/1. Metadata and transports are JSON text.
--
-- # No foreign keys
--
-- None of the user_id columns declares REFERENCES users(id), deliberately.
-- sulis never promises that a session, token, credential, or recovery code
-- lives in the same database as the user row it names — an adopter may keep
-- users in a separate service entirely — and storetest exercises each store
-- in isolation, with user IDs that were never inserted anywhere. The indexes
-- a foreign key would have implied are declared explicitly instead. Add the
-- REFERENCES clauses (and PRAGMA foreign_keys = ON) if your users table is
-- co-located and you want the cascade.

CREATE TABLE IF NOT EXISTS users (
    id                    TEXT    PRIMARY KEY,
    -- COLLATE NOCASE makes the UNIQUE index below case-insensitive. sulis
    -- normalizes an address to lowercase long before a store sees it, so for
    -- every address sulis itself produces this changes nothing; where it
    -- matters is a caller that bypasses normalization, and there refusing to
    -- create the confusable duplicate is the safer of the two behaviors.
    email                 TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash         TEXT    NOT NULL DEFAULT '',
    created_at            TEXT    NOT NULL,
    updated_at            TEXT    NOT NULL,
    metadata              TEXT,
    email_verified_at     TEXT,
    pending_email         TEXT    NOT NULL DEFAULT '',
    disabled_at           TEXT,
    disabled_reason       TEXT    NOT NULL DEFAULT '',
    locked_until          TEXT,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    -- Optimistic concurrency. UpdateUser writes
    -- "... WHERE id = ? AND version = ?" and reports zero affected rows as
    -- sulis.ErrConcurrentUpdate; without this column a stale read could
    -- restore a password hash the user just rotated away from.
    version               INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE IF NOT EXISTS sessions (
    id               TEXT PRIMARY KEY,
    user_id          TEXT NOT NULL,
    -- The SHA-256 hash of the session token. The raw token is never stored;
    -- it exists only in the response that issued it.
    token_hash       TEXT NOT NULL UNIQUE,
    expires_at       TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    authenticated_at TEXT NOT NULL,
    method           TEXT NOT NULL DEFAULT '',
    last_seen_at     TEXT NOT NULL,
    -- NULL whenever idle expiry is disabled. TouchSession writes NULL rather
    -- than leaving a stale deadline behind, or an application that turns
    -- WithIdleTimeout off would keep enforcing the old one.
    idle_expires_at  TEXT,
    ip               TEXT NOT NULL DEFAULT '',
    user_agent       TEXT NOT NULL DEFAULT '',
    metadata         TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions (user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE IF NOT EXISTS tokens (
    id         TEXT    PRIMARY KEY,
    -- Empty for a magic-link token issued before the account exists.
    user_id    TEXT    NOT NULL DEFAULT '',
    token_hash TEXT    NOT NULL UNIQUE,
    purpose    TEXT    NOT NULL,
    expires_at TEXT    NOT NULL,
    created_at TEXT    NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    email      TEXT    NOT NULL DEFAULT '',
    nonce_hash TEXT    NOT NULL DEFAULT ''
) STRICT;

-- ConsumeToken keys on (token_hash, purpose) together: purpose is part of the
-- lookup, not a field checked afterwards, so a two-factor token presented to
-- the password-reset flow matches nothing at all.
CREATE INDEX IF NOT EXISTS tokens_hash_purpose_idx ON tokens (token_hash, purpose);
CREATE INDEX IF NOT EXISTS tokens_user_purpose_idx ON tokens (user_id, purpose);
CREATE INDEX IF NOT EXISTS tokens_expires_at_idx ON tokens (expires_at);

CREATE TABLE IF NOT EXISTS passkey_credentials (
    -- The store's own opaque ID, which is what DeleteCredential and
    -- RenameCredential address a credential by.
    id               TEXT    PRIMARY KEY,
    user_id          TEXT    NOT NULL,
    -- The raw WebAuthn credential ID, which is what GetCredentialByID and
    -- UpdateCredentialAfterLogin address it by.
    credential_id    BLOB    NOT NULL UNIQUE,
    public_key       BLOB    NOT NULL,
    attestation_type TEXT    NOT NULL DEFAULT '',
    aaguid           BLOB,
    -- go-webauthn re-reads sign_count and backup_state on every later
    -- ceremony; a store that drops either breaks the credential's NEXT login
    -- rather than this one.
    sign_count       INTEGER NOT NULL DEFAULT 0,
    name             TEXT    NOT NULL DEFAULT '',
    transports       TEXT,
    backup_eligible  INTEGER NOT NULL DEFAULT 0,
    backup_state     INTEGER NOT NULL DEFAULT 0,
    discoverable     INTEGER NOT NULL DEFAULT 0,
    last_used_at     TEXT,
    created_at       TEXT    NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS passkey_credentials_user_id_idx ON passkey_credentials (user_id);

CREATE TABLE IF NOT EXISTS passkey_challenges (
    -- Opaque, scoped by ceremony ("register:<userID>", "login:<ceremonyID>"),
    -- never a bare user ID, so two concurrent ceremonies for one user cannot
    -- clobber each other's challenge.
    challenge_key TEXT PRIMARY KEY,
    session_data  BLOB NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS passkey_challenges_expires_at_idx ON passkey_challenges (expires_at);

-- The active (verified) and pending (unverified) TOTP slots are two tables,
-- not one table with a flag, because the interface promises at most one of
-- EACH per user. user_id is the primary key of both, so that promise is a
-- constraint rather than a convention, and ConfirmEnrollment's promotion is
-- one DELETE ... RETURNING feeding one upsert.
CREATE TABLE IF NOT EXISTS totp_active (
    user_id           TEXT    PRIMARY KEY,
    id                TEXT    NOT NULL,
    -- Opaque to this package: ciphertext when totp is configured with an
    -- Encryptor, the base32 secret otherwise. A store cannot tell.
    secret            TEXT    NOT NULL,
    last_used_counter INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT    NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS totp_pending (
    user_id    TEXT PRIMARY KEY,
    id         TEXT NOT NULL,
    secret     TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

-- Only hashes; the plaintext codes exist once, in the response that generated
-- them. The composite primary key is also the lookup index ConsumeCode needs,
-- and it scopes a code to its owner: presenting another user's code hash
-- matches no row.
CREATE TABLE IF NOT EXISTS recovery_codes (
    user_id    TEXT NOT NULL,
    code_hash  TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, code_hash)
) STRICT;
