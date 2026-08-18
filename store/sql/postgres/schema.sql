-- Schema for the PostgreSQL reference stores in this package.
--
-- It is the sibling of store/sql/sqlite/schema.sql and deliberately mirrors
-- it table for table, constraint for constraint: every constraint here exists
-- because a store interface in sulis documents behavior a Go implementation
-- cannot be trusted to remember. The UNIQUE index on lower(users.email) is
-- what actually closes the two-accounts-claiming-one-address race (UserStore's
-- doc comment says so in as many words), the version column is what makes
-- UpdateUser's compare-and-swap expressible as one statement, and the separate
-- totp_active/totp_pending tables are what stop a racing enrollment from
-- replacing a working second factor.
--
-- Applied by Migrate, which runs the whole file in one transaction. It is also
-- exported as postgres.Schema so an adopter can feed it to their own migration
-- tool instead. Nothing here is schema-qualified, so the objects land in the
-- first schema on the connection's search_path — which is what lets one
-- database hold several isolated copies (the conformance tests use one schema
-- per test function).
--
-- # Types
--
-- Timestamps are TEXT in a fixed-width UTC layout
-- ("2006-01-02T15:04:05.000000000Z"), NOT timestamptz, and that is the one
-- place this schema knowingly departs from idiomatic PostgreSQL. timestamptz
-- resolves to one microsecond and rounds anything finer away
-- (12:34:56.123456789Z is stored as 12:34:56.123457Z — confirmed against
-- PostgreSQL 17), while a Go time.Time carries nanoseconds and the session
-- contract requires an exact round trip: storetest asserts
-- got.ExpiresAt.Equal(sess.ExpiresAt) on a value built from an untruncated
-- time.Now(). Nine fractional digits round-trip a time.Time without losing
-- precision, fixed width means byte order is chronological order, and the
-- expiry sweeps below compare with "<" on exactly that order, so the indexes
-- still serve them. Store a timestamptz alongside if you want to query these
-- rows with date_trunc; do not store one INSTEAD.
--
-- Everything else is native: bytea for the WebAuthn blobs, boolean for the
-- flags SQLite had to spell as INTEGER 0/1, jsonb for metadata and transports,
-- bigint for the counters that carry a Go uint64 or uint32.
--
-- # Case-insensitive e-mail
--
-- users.email is plain text with a UNIQUE index on lower(email) rather than a
-- citext column. citext needs CREATE EXTENSION, which is a privilege plenty of
-- managed PostgreSQL users do not have and a migration step an adopter should
-- not need; the functional index needs nothing. The semantics match the SQLite
-- store's COLLATE NOCASE for every address sulis itself produces, because
-- sulis normalizes to lowercase long before a store sees one. GetUserByEmail
-- queries lower(email) = lower($1) so the lookup uses this index rather than
-- silently sequential-scanning.
--
-- # No foreign keys
--
-- None of the user_id columns declares REFERENCES users(id), deliberately.
-- sulis never promises that a session, token, credential, or recovery code
-- lives in the same database as the user row it names — an adopter may keep
-- users in a separate service entirely — and storetest exercises each store in
-- isolation, with user IDs that were never inserted anywhere. The indexes a
-- foreign key would have implied are declared explicitly instead. Add the
-- REFERENCES clauses if your users table is co-located and you want the
-- cascade.

CREATE TABLE IF NOT EXISTS users (
    id                    text    PRIMARY KEY,
    email                 text    NOT NULL,
    password_hash         text    NOT NULL DEFAULT '',
    created_at            text    NOT NULL,
    updated_at            text    NOT NULL,
    metadata              jsonb,
    email_verified_at     text,
    pending_email         text    NOT NULL DEFAULT '',
    disabled_at           text,
    disabled_reason       text    NOT NULL DEFAULT '',
    locked_until          text,
    failed_login_attempts integer NOT NULL DEFAULT 0,
    -- Optimistic concurrency. UpdateUser writes
    -- "... WHERE id = $1 AND version = $2" and reports zero affected rows as
    -- sulis.ErrConcurrentUpdate; without this column a stale read could
    -- restore a password hash the user just rotated away from.
    version               bigint  NOT NULL DEFAULT 0
);

-- The case-insensitive uniqueness UserStore requires. A caller that bypassed
-- sulis's own normalization and tried to create "Someone@Example.test"
-- alongside "someone@example.test" is refused here rather than given a
-- confusable duplicate account.
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_key ON users (lower(email));

CREATE TABLE IF NOT EXISTS sessions (
    id               text PRIMARY KEY,
    user_id          text NOT NULL,
    -- The SHA-256 hash of the session token. The raw token is never stored;
    -- it exists only in the response that issued it.
    token_hash       text NOT NULL UNIQUE,
    expires_at       text NOT NULL,
    created_at       text NOT NULL,
    authenticated_at text NOT NULL,
    method           text NOT NULL DEFAULT '',
    last_seen_at     text NOT NULL,
    -- NULL whenever idle expiry is disabled. TouchSession writes NULL rather
    -- than leaving a stale deadline behind, or an application that turns
    -- WithIdleTimeout off would keep enforcing the old one.
    idle_expires_at  text,
    ip               text NOT NULL DEFAULT '',
    user_agent       text NOT NULL DEFAULT '',
    metadata         jsonb
);

CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions (user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE IF NOT EXISTS tokens (
    id         text    PRIMARY KEY,
    -- Empty for a magic-link token issued before the account exists.
    user_id    text    NOT NULL DEFAULT '',
    token_hash text    NOT NULL UNIQUE,
    purpose    text    NOT NULL,
    expires_at text    NOT NULL,
    created_at text    NOT NULL,
    used       boolean NOT NULL DEFAULT false,
    email      text    NOT NULL DEFAULT '',
    nonce_hash text    NOT NULL DEFAULT ''
);

-- ConsumeToken keys on (token_hash, purpose) together: purpose is part of the
-- lookup, not a field checked afterwards, so a two-factor token presented to
-- the password-reset flow matches nothing at all.
CREATE INDEX IF NOT EXISTS tokens_hash_purpose_idx ON tokens (token_hash, purpose);
CREATE INDEX IF NOT EXISTS tokens_user_purpose_idx ON tokens (user_id, purpose);
CREATE INDEX IF NOT EXISTS tokens_expires_at_idx ON tokens (expires_at);

CREATE TABLE IF NOT EXISTS passkey_credentials (
    -- The store's own opaque ID, which is what DeleteCredential and
    -- RenameCredential address a credential by.
    id               text    PRIMARY KEY,
    user_id          text    NOT NULL,
    -- The raw WebAuthn credential ID, which is what GetCredentialByID and
    -- UpdateCredentialAfterLogin address it by.
    credential_id    bytea   NOT NULL UNIQUE,
    public_key       bytea   NOT NULL,
    attestation_type text    NOT NULL DEFAULT '',
    aaguid           bytea,
    -- go-webauthn re-reads sign_count and backup_state on every later
    -- ceremony; a store that drops either breaks the credential's NEXT login
    -- rather than this one. bigint, not integer: the Go field is a uint32 and
    -- its top half does not fit in a signed 32-bit column.
    sign_count       bigint  NOT NULL DEFAULT 0,
    name             text    NOT NULL DEFAULT '',
    transports       jsonb,
    backup_eligible  boolean NOT NULL DEFAULT false,
    backup_state     boolean NOT NULL DEFAULT false,
    discoverable     boolean NOT NULL DEFAULT false,
    last_used_at     text,
    created_at       text    NOT NULL
);

CREATE INDEX IF NOT EXISTS passkey_credentials_user_id_idx ON passkey_credentials (user_id);

CREATE TABLE IF NOT EXISTS passkey_challenges (
    -- Opaque, scoped by ceremony ("register:<userID>", "login:<ceremonyID>"),
    -- never a bare user ID, so two concurrent ceremonies for one user cannot
    -- clobber each other's challenge.
    challenge_key text  PRIMARY KEY,
    session_data  bytea NOT NULL,
    created_at    text  NOT NULL,
    expires_at    text  NOT NULL
);

CREATE INDEX IF NOT EXISTS passkey_challenges_expires_at_idx ON passkey_challenges (expires_at);

-- The active (verified) and pending (unverified) TOTP slots are two tables,
-- not one table with a flag, because the interface promises at most one of
-- EACH per user. user_id is the primary key of both, so that promise is a
-- constraint rather than a convention, and ConfirmEnrollment's promotion is
-- one DELETE ... RETURNING feeding one upsert.
CREATE TABLE IF NOT EXISTS totp_active (
    user_id           text   PRIMARY KEY,
    id                text   NOT NULL,
    -- Opaque to this package: ciphertext when totp is configured with an
    -- Encryptor, the base32 secret otherwise. A store cannot tell.
    secret            text   NOT NULL,
    last_used_counter bigint NOT NULL DEFAULT 0,
    created_at        text   NOT NULL
);

CREATE TABLE IF NOT EXISTS totp_pending (
    user_id    text PRIMARY KEY,
    id         text NOT NULL,
    secret     text NOT NULL,
    created_at text NOT NULL
);

-- Only hashes; the plaintext codes exist once, in the response that generated
-- them. The composite primary key is also the lookup index ConsumeCode needs,
-- and it scopes a code to its owner: presenting another user's code hash
-- matches no row.
CREATE TABLE IF NOT EXISTS recovery_codes (
    user_id    text NOT NULL,
    code_hash  text NOT NULL,
    created_at text NOT NULL,
    PRIMARY KEY (user_id, code_hash)
);
