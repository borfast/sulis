# UUID identifiers: design

Date: 2026-10-18. Issue: #36. The matching gorfast change
(borfast/gorfast#8) gets its own spec once this ships.

## 1. Purpose

Sulis generates every account, session, token and credential ID with
`generateID`, which hex-encodes 16 random bytes into a `string`. Nothing marks
these values as IDs, so any string can be passed where one is expected, and
stores keep them as text.

This spec makes every ID a `uuid.UUID` from the standard library `uuid`
package (added in Go 1.27, which Sulis already requires), generated as
version 7.

Nothing uses Sulis yet, so this is a breaking change with no upgrade path. The
code and both SQL schemas change as if UUIDs had been used from the start.

## 2. Decisions and the alternatives rejected

- **Standard library `uuid.UUID`.** Rejected: `github.com/google/uuid`, which
  would become a direct dependency of every consumer, and a Sulis-owned `ID`
  type, which applications would have to convert to and from.
- **One type for every ID.** Rejected: a type per entity
  (`type UserID uuid.UUID`). It would stop a session ID being passed as a user
  ID, but a defined type loses `uuid.UUID`'s methods, so Sulis would redefine
  `String` and `MarshalText` for each, and callers would convert at every
  boundary.
- **Version 7 for every ID**, so new rows go at the end of each index. The cost
  is that an ID contains its creation time to the millisecond, so a user ID
  shown in a URL tells when the account was created. The README says so.
  Rejected: version 4 for some or all IDs.
- **`uuid.Nil()` means "no ID"** (section 4 lists where). Rejected:
  `*uuid.UUID` with nil meaning "no ID", which would make `Token.UserID` and
  `Event.UserID` pointers that every reader must check for nil.
- **The passkey user handle is the 16 UUID bytes.** Rejected: the bytes of the
  text form, which only made sense while IDs were strings.
- **Schemas edited in place, with no migration**, because no database has data
  to migrate.
- **SQL conversion helpers stay unexported, one per store package.** Rejected:
  an exported `Scanner`/`Valuer` wrapper in Sulis. An application with its own
  SQL layer converts in a few lines, and gorfast needs a Bun-specific type
  anyway.

## 3. Which values become `uuid.UUID`

Every field, parameter and return value that carries an ID Sulis generated:

- **Root package:** `User.ID`; `Session.ID` and `Session.UserID`; `Token.ID`
  and `Token.UserID`; `Event.UserID` and `Event.SessionID`; the unexported
  `Authentication.userID`; and every `userID`, `sessionID` and `id`
  parameter, for example in `IssueSessionUnchecked`, `RevokeSession`,
  `DisableUser`, `ChangePassword`, `CompleteTwoFactor` and
  `SecondFactorChecker.HasSecondFactor`.
- **`totp`:** `Credential.ID`, `Credential.UserID`, `pendingID`, and every
  `userID` parameter.
- **`passkey`:** `Credential.ID`, `Credential.UserID`, `User.ID`, every
  `userID` parameter, and the ceremony ID. `BeginLogin` and
  `BeginDiscoverableLogin` return it; `FinishLogin`, `FinishLoginResponse`,
  `FinishDiscoverableLogin` and `FinishDiscoverableLoginResponse` take it.
- **`recovery`:** every `userID` parameter.
- **Every subpackage's `Event.UserID`.**

These keep their current types:

- `string`: raw tokens; token, nonce and recovery code hashes; emails;
  rate-limiter keys; and `ChallengeStore` keys, which are built from an ID's
  text form (section 7).
- `[]byte`: the WebAuthn `CredentialID` and `AAGUID`, which the authenticator
  supplies.

## 4. Generation and `uuid.Nil()`

- `uuid.NewV7()` replaces the three copies of `generateID` (root, `totp`,
  `passkey`), which are deleted.
- `uuid.Nil()` means "no ID":
  - a magic-link token issued before the account exists has `UserID` set to
    `uuid.Nil()`;
  - an event with no user has `UserID` set to `uuid.Nil()`;
  - the zero `Authentication` has `userID` set to `uuid.Nil()`, and
    `IssueSession` still rejects it with `ErrNotAuthenticated`.
- Each test of an ID against `""` becomes a test against `uuid.Nil()`.
- A method given `uuid.Nil()` as an ID behaves as it does today when given `""`:
  the lookup finds nothing, and the method returns its usual not-found error.
  There is no new validation.

## 5. Store interfaces, `memstore` and `storetest`

- The fields and parameters named in section 3 become `uuid.UUID` in
  `UserStore`, `SessionStore`, `TokenStore`, `totp.Store`, `passkey.Store` and
  `recovery.Store`. `passkey.ChallengeStore` does not change.
- `memstore` keys its maps by `uuid.UUID`.
- `storetest` creates IDs with `uuid.NewV7()`. `uniqueID` stays for the
  values that are not IDs: challenge keys, hashes and names.
- New check in `RunTokenStore`: a token created with `UserID` set to
  `uuid.Nil()` comes back from `ConsumeToken` with `UserID` set to `uuid.Nil()`.

## 6. SQL schemas and stores (`store/sql`)

Both `schema.sql` files are edited in place:

- Postgres: every `id` and `user_id` column is `uuid`.
- SQLite: every `id` and `user_id` column is `BLOB` with
  `CHECK (length(<column>) = 16)`.
- `tokens.user_id` is nullable in both, NULL meaning no user, replacing
  `NOT NULL DEFAULT ''`. The stores write NULL for `uuid.Nil()` and read NULL
  back as `uuid.Nil()`.
- The comments that describe IDs as text are updated. The "No foreign keys"
  section does not change.

`store/sql/postgres` and `store/sql/sqlite` each get an unexported helper that
turns a `uuid.UUID` into a query argument (the text form for Postgres, the 16
bytes for SQLite, NULL for `uuid.Nil()` in `tokens.user_id`) and scans a column
back into a `uuid.UUID`.

## 7. Passkeys

- `passkey.User.ID` is a `uuid.UUID`, and `WebAuthnID()` returns its 16 bytes
  as the user handle.
- `FinishDiscoverableLoginResponse` compares the user handle the authenticator
  returns, byte for byte, with the stored credential's `UserID`. A handle of
  any other length fails the same way a mismatch does today, with
  `ErrChallengeFailed`.
- Challenge keys stay strings: `"register:" + user.ID.String()`,
  `"login:" + ceremonyID.String()` and `"discover:" + ceremonyID.String()`.

## 8. Example app

`examples/webapp` parses IDs from cookies and form values with `uuid.Parse`. A
malformed cookie value is treated as a missing cookie. A malformed form value
gets a 400 response.

## 9. Docs and release

- `CHANGELOG.md` gets a v0.4.0 entry: IDs are `uuid.UUID`, both schemas
  changed, and there is no upgrade path, so existing databases must be
  recreated.
- `README.md`: signatures and examples updated; a note that version 7 IDs
  contain their creation time; the passkey section says the user handle is the
  16 ID bytes.
- `store/sql/go.mod` and `examples/webapp/go.mod` require v0.4.0.
- Release tags `v0.4.0` and `store/sql/v0.4.0`. Tagging and pushing wait for
  the maintainer's approval.

## 10. Testing

Tests come first. New tests:

- every generated ID (user, session, token, TOTP credential, passkey
  credential, ceremony) is version 7;
- discoverable login with a user handle of the wrong length returns
  `ErrChallengeFailed`;
- the `uuid.Nil()` token check from section 5, run against `memstore` and both
  SQL stores;
- in `store/sql/sqlite`, a raw `INSERT` with a 15-byte `id` is refused by the
  `CHECK`.

Existing tests move to the new types. `go test -race ./...` must pass in the
root module, in `store/sql` with Postgres running, and in `examples/webapp`,
along with the linters CI already runs (staticcheck, gosec, govulncheck).

## 11. Out of scope

- gorfast `auth/bunstore` (borfast/gorfast#8), in a separate spec after
  v0.4.0.
- Any migration from text IDs.
- Per-entity ID types.
