# UUID Identifiers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every ID Sulis generates is a version 7 `uuid.UUID`, in the API, the reference stores and both SQL schemas, as if UUIDs had been used from the start.

**Architecture:** The root package does not import `totp`, `passkey` or `recovery`, so the root types move first (Tasks 1 to 3: root module, then `store/sql`, then `examples/webapp`), and each subpackage then moves in one task that covers every module (Tasks 4 to 6). Docs come last (Task 7).

**Tech Stack:** Go 1.27 (standard library `uuid`), `database/sql` with pgx v5 (Postgres) and modernc SQLite, go-webauthn.

**Spec:** `docs/superpowers/specs/2026-10-18-uuid-identifiers-design.md`

## Global Constraints

- Import the standard library package `uuid` (Go 1.27). Add no module dependency.
- Generate every ID with `uuid.NewV7()`.
- `uuid.Nil` means "no ID". Test IDs against `uuid.Nil`, never against a string.
- Stay `string`: raw tokens; token, nonce and recovery code hashes; emails; rate-limiter keys; `ChallengeStore` keys. Stay `[]byte`: the WebAuthn `CredentialID` and `AAGUID`.
- Rate-limiter and challenge keys are built from an ID's text form, for example `"totp:" + userID.String()`.
- Schemas are edited in place, with no migration code. Postgres ID columns are `uuid`. SQLite ID columns are `BLOB` with `CHECK (length(<column>) = 16)`. `tokens.user_id` is nullable in both, NULL meaning no user.
- Tests check version 7 with `u[6]>>4 == 7`.
- A transitional conversion (an ID turned into a string, or parsed, only because another package has not moved yet) carries the comment `// transitional: Task N`, where N is the task that removes it. After Task 6, `grep -rn 'transitional:' .` finds nothing.
- After Task 1, `store/sql` does not compile until Task 2, and `examples/webapp` does not compile until Task 3. Each task's verification names the modules that must pass.
- New code comments are at most 2 lines. No em-dashes anywhere, and no en-dash or spaced hyphen in their place. Plain, literal English.
- Commits are signed, with a sentence-case subject and no prefix, a body of at most 5 lines, and no trailers.
- GitNexus (Sulis `CLAUDE.md`): run `impact` before editing a function; run `git add`, then `detect-changes --scope all`, then commit.
- A module passes when `gofmt -l .` prints nothing, `go vet ./...` is clean and `go test -race -count=1 ./...` passes. `store/sql` runs with `SULIS_POSTGRES_TEST_URL` set; a skipped Postgres test is not a pass.

## Review Focus

1. A malformed ID in a request to the example app (the revoke form's `session_id`, the passkey delete form's `credential_id`, the passkey login cookies) is treated as missing or gets a 400, never a panic or a 500. Tests: Task 3 and Task 6.
2. The slog event sink leaves out `user_id` and `session_id` for `uuid.Nil` instead of logging the all-zero UUID. Test: Task 1.
3. `DeleteUserTokens(ctx, uuid.Nil, purpose)` deletes nothing in every store, including tokens issued before an account exists. Test: Task 1 (`storetest`), run against SQL in Task 2.
4. A stored ID value of the wrong size makes a SQL store return an error, not a zero UUID. Test: Task 2.
5. `IssueSessionUnchecked(ctx, uuid.Nil, method)` returns `ErrUserNotFound`, not a session. Test: Task 1.

---

### Task 1: Root package, `memstore` and `storetest` for users, sessions and tokens

**Files:**
- Modify: `user.go`, `session.go`, `token.go`, `issue.go`, `events.go`, `sulis.go`, `magiclink.go`, `changeemail.go`, `emailverification.go`, `status.go`, `twofactor.go`, and any other root file the compiler names
- Modify: `memstore/user.go`, `memstore/session.go`, `memstore/token.go`
- Modify: `storetest/user.go`, `storetest/session.go`, `storetest/token.go`
- Test: `id_test.go` (new, package `sulis_test`), `storetest/token.go`, and every root test the type change breaks

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - Fields: `User.ID`, `Session.ID`, `Session.UserID`, `Token.ID`, `Token.UserID`, `Event.UserID`, `Event.SessionID` are `uuid.UUID`.
  - `UserStore`: `GetUserByID(ctx, id uuid.UUID)`, `DeleteUser(ctx, id uuid.UUID)`.
  - `SessionStore`: `ListUserSessions(ctx, userID uuid.UUID)`, `DeleteSession(ctx, userID, id uuid.UUID)`, `DeleteUserSessions(ctx, userID uuid.UUID)`, `DeleteUserSessionsExcept(ctx, userID, keepSessionID uuid.UUID)`, `UpdateAuthenticatedAt(ctx, id uuid.UUID, at time.Time)`, `TouchSession(ctx, id uuid.UUID, lastSeen time.Time, idleExpires *time.Time)`.
  - `TokenStore`: `DeleteUserTokens(ctx, userID uuid.UUID, purpose TokenPurpose)`.
  - `SecondFactorChecker.HasSecondFactor(ctx, userID uuid.UUID) (bool, error)`.
  - `*Sulis` methods whose `userID` or `sessionID` parameter becomes `uuid.UUID`, other parameters unchanged: `ChangeEmail`, `CreateEmailVerificationToken`, `IssueSessionUnchecked`, `ListUserSessions`, `DisableUser`, `EnableUser`, `ChangePassword`, `SetInitialPassword`, `RevokeSession`, `RevokeAllSessions`, `CreateTwoFactorToken`, `CompleteTwoFactor`.
  - `storetest` helpers: `newSession(userID uuid.UUID)`, `newTokenFor(userID uuid.UUID, purpose)`. `uniqueID` stays for values that are not IDs.

- [ ] **Step 1: Write the failing tests**

In `id_test.go`:
- `TestGeneratedIDsAreVersion7`: on a `memstore`-backed `Sulis` whose `TokenStore` is wrapped to record the `*Token` passed to `CreateToken`, call `Register` (which returns the user and a session) and then `CreatePasswordResetToken` for that user's email. Assert `u[6]>>4 == 7` for the user ID, the session ID and the recorded token ID.
- `TestSlogSinkOmitsNilIDs`: emit `Event{Kind: EventLoginFailed}` through `NewSlogSink` into a JSON handler writing to a buffer; the record has no `user_id` and no `session_id` key. Emit again with `UserID: id`; `user_id` equals `id.String()`.
- `TestIssueSessionUncheckedNilUserReturnsErrUserNotFound`: `IssueSessionUnchecked(ctx, uuid.Nil, AuthMethodPassword)` returns `errors.Is(err, ErrUserNotFound)` and a nil session.

In `storetest/token.go`, inside `RunTokenStore`:
- `ConsumeTokenWithoutUserReturnsNilUserID`: create a token with `UserID: uuid.Nil`; `ConsumeToken` returns it with `UserID == uuid.Nil`.
- `DeleteUserTokensForNilUserDeletesNothing`: create a token with `UserID: uuid.Nil`, call `DeleteUserTokens(ctx, uuid.Nil, purpose)` (no error), then `ConsumeToken` still returns the token.

- [ ] **Step 2: Run them to verify they fail**

Run in the repository root: `go vet ./...`
Expected: compile errors, because `uuid.Nil` is not assignable to string fields.

- [ ] **Step 3: Change the types**

Apply the Interfaces block. Replace the root `generateID` with `uuid.NewV7()` and delete it. Every `== ""` or `!= ""` test of an ID becomes a test against `uuid.Nil`; the slog sink writes `id.String()` and skips `uuid.Nil`. `memstore` keys its maps by `uuid.UUID`, and its `DeleteUserTokens` returns nil without deleting when `userID == uuid.Nil`. `storetest` creates IDs with `uuid.NewV7()`. Where a root test passes a root ID to `totp`, `passkey` or `recovery`, convert with `.String()` and mark it `// transitional: Task 4`, `5` or `6`.

- [ ] **Step 4: Run the root module**

Run in the repository root: `gofmt -l .`, `go vet ./...`, `go test -race -count=1 ./...`
Expected: no output from gofmt, vet clean, all packages `ok`. `store/sql` and `examples/webapp` are not expected to compile yet.

- [ ] **Step 5: Commit**

```bash
git add <the files above>
git commit -m "Use uuid.UUID for user, session and token IDs"
```

### Task 2: `store/sql` users, sessions and tokens

**Files:**
- Create: `store/sql/postgres/ids.go`, `store/sql/postgres/ids_internal_test.go`, `store/sql/sqlite/ids.go`, `store/sql/sqlite/ids_internal_test.go`
- Modify: `store/sql/postgres/{user,session,token}.go`, `store/sql/sqlite/{user,session,token}.go`
- Modify: `store/sql/postgres/schema.sql`, `store/sql/sqlite/schema.sql` (tables `users`, `sessions`, `tokens`, and the "Types" comment)
- Test: `store/sql/sqlite/sqlite_test.go`

**Interfaces:**
- Consumes: Task 1's store interfaces.
- Produces, in both `postgres` and `sqlite` (unexported):

```go
// idArg turns an ID into a query argument: its text form for Postgres, its 16 bytes for SQLite.
func idArg(id uuid.UUID) any
// nullableIDArg is idArg, except that uuid.Nil becomes NULL.
func nullableIDArg(id uuid.UUID) any
// scanID scans an ID column into dst: NULL gives uuid.Nil, anything malformed is an error.
func scanID(dst *uuid.UUID) sql.Scanner
```

Postgres `scanID` accepts a `string` or `[]byte` holding the text form. SQLite `scanID` accepts a `[]byte` of exactly 16 bytes.

- [ ] **Step 1: Write the failing tests**

- `postgres.TestScanIDParsesTextAndNull` (internal): `Scan(id.String())` gives `id`; `Scan([]byte(id.String()))` gives `id`; `Scan(nil)` gives `uuid.Nil`; `Scan("not-a-uuid")` returns an error.
- `sqlite.TestScanIDRequiresSixteenBytes` (internal): `Scan(id[:])` gives `id`; `Scan(nil)` gives `uuid.Nil`; `Scan(make([]byte, 15))` returns an error; `Scan(id.String())` returns an error.
- `sqlite_test.TestSchemaRefusesShortID`: after `Migrate`, a raw `INSERT INTO users (id, email, created_at, updated_at) VALUES (?, ?, ?, ?)` with a 15-byte `id` returns an error.

- [ ] **Step 2: Run them to verify they fail**

Run in `store/sql`: `go vet ./...`
Expected: compile errors (Task 1's types, and the undefined helpers).

- [ ] **Step 3: Implement**

Write the helpers. Edit both schemas: `users.id`, `sessions.id`, `sessions.user_id`, `tokens.id` become `uuid` (Postgres) or `BLOB NOT NULL CHECK (length(<column>) = 16)` (SQLite); `tokens.user_id` becomes nullable with no default, with the same `CHECK` on SQLite. Add one sentence on ID columns to each "Types" comment. Every ID passed to or read from these three tables goes through the helpers, with `nullableIDArg` for `tokens.user_id`.

- [ ] **Step 4: Run `store/sql`**

Run in `store/sql`, with `SULIS_POSTGRES_TEST_URL` set: `gofmt -l .`, `go vet ./...`, `go test -race -count=1 -v ./... 2>&1 | grep -E -- '^(ok|FAIL)|--- (FAIL|SKIP)'`
Expected: both packages `ok`, no `--- FAIL`, no `--- SKIP`. The root module still passes.

- [ ] **Step 5: Commit**

```bash
git commit -m "Store user, session and token IDs as UUIDs in store/sql"
```

### Task 3: Example app, root types

**Files:**
- Modify: `examples/webapp/app.go` (`secondFactors.HasSecondFactor`), `examples/webapp/handlers_account.go` (revoke form), `examples/webapp/handlers_mfa.go` (`pending2FA` holds `uuid.UUID`), and any other file the compiler names
- Test: `examples/webapp/account_test.go`

**Interfaces:**
- Consumes: Task 1's `*Sulis` methods and `SecondFactorChecker`.
- Produces: nothing new.

- [ ] **Step 1: Write the failing test**

`TestRevokeSessionWithMalformedIDReturns400`: a signed-in user posts `session_id=not-a-uuid` with a valid CSRF token to the revoke endpoint; the response is 400, and the user's session cookie still validates.

- [ ] **Step 2: Run it to verify it fails**

Run in `examples/webapp`: `go vet ./...`
Expected: compile errors from Task 1's types.

- [ ] **Step 3: Implement**

Parse `session_id` with `uuid.Parse` and answer a parse error with 400. Pass root IDs into `totp`, `passkey` and `recovery` with `.String()` marked `// transitional: Task N`.

- [ ] **Step 4: Run all three modules**

Run the module check (Global Constraints) in the root, `store/sql` and `examples/webapp`.
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git commit -m "Use UUID session IDs in the example app"
```

### Task 4: TOTP IDs in every module

**Files:**
- Modify: `totp/store.go`, `totp/totp.go`, `totp/*_test.go`
- Modify: `memstore/totp.go`, `storetest/totp.go`
- Modify: `store/sql/{postgres,sqlite}/totp.go`, both `schema.sql` (`totp_active`, `totp_pending`: `user_id` and `id`)
- Modify: root tests and `examples/webapp` files marked `// transitional: Task 4`

**Interfaces:**
- Consumes: Task 2's `idArg` and `scanID`.
- Produces:
  - `totp.Credential.ID` and `totp.Credential.UserID` are `uuid.UUID`.
  - `totp.Store`: `GetActiveTOTP(ctx, userID uuid.UUID)`, `GetPendingTOTP(ctx, userID uuid.UUID)`, `ConfirmEnrollment(ctx, userID, pendingID uuid.UUID, counter uint64)`, `DeleteTOTP(ctx, userID uuid.UUID)`.
  - `totp.Service`: `Enroll(ctx, userID uuid.UUID, accountName string)`, `ReplaceEnrollment(ctx, userID uuid.UUID, accountName string)`, `ConfirmEnrollment(ctx, userID uuid.UUID, code string)`, `Validate(ctx, userID uuid.UUID, code string)`, `Unenroll(ctx, userID uuid.UUID)`.
  - Rate-limiter key `"totp:" + userID.String()`.

- [ ] **Step 1: Write the failing test**

`totp.TestEnrollCreatesVersion7CredentialID`: `Enroll` for a user on a `newMemTOTPStore()`, read the pending credential back with `GetPendingTOTP`, and assert `pending.ID[6]>>4 == 7`.

- [ ] **Step 2: Run it to verify it fails**

Run in the root: `go vet ./totp/`
Expected: compile errors.

- [ ] **Step 3: Implement**

Apply the Interfaces block; replace `totp`'s `generateID` with `uuid.NewV7()` and delete it. Edit both schemas' TOTP tables as in Task 2 and route their IDs through the helpers. Remove every `// transitional: Task 4` conversion.

- [ ] **Step 4: Run all three modules**

Expected: all pass, and `grep -rn 'transitional: Task 4' .` finds nothing.

- [ ] **Step 5: Commit**

```bash
git commit -m "Use uuid.UUID for TOTP IDs"
```

### Task 5: Recovery code user IDs in every module

**Files:**
- Modify: `recovery/store.go`, `recovery/recovery.go`, `recovery/events.go`, `recovery/*_test.go`
- Modify: `memstore/recovery.go`, `storetest/recovery.go`
- Modify: `store/sql/{postgres,sqlite}/recovery.go`, both `schema.sql` (`recovery_codes.user_id`)
- Modify: files marked `// transitional: Task 5`

**Interfaces:**
- Consumes: Task 2's helpers.
- Produces:
  - `recovery.Store`: `ReplaceCodes(ctx, userID uuid.UUID, hashes []string)`, `ConsumeCode(ctx, userID uuid.UUID, hash string)`, `CountCodes(ctx, userID uuid.UUID)`, `DeleteCodes(ctx, userID uuid.UUID)`.
  - `recovery.Service`: `Generate`, `Consume`, `Remaining`, `Disable` take `userID uuid.UUID`.
  - `recovery.Event.UserID` is `uuid.UUID`. Rate-limiter key `"recovery:" + userID.String()`.

- [ ] **Step 1: Update the tests to the new types**

In `recovery/*_test.go` and `storetest/recovery.go`, user IDs come from `uuid.NewV7()`. No new behaviour is added, so the existing tests are the check.

- [ ] **Step 2: Run them to verify they fail**

Run in the root: `go vet ./recovery/ ./storetest/`
Expected: compile errors.

- [ ] **Step 3: Implement**

Apply the Interfaces block. Edit `recovery_codes.user_id` in both schemas as in Task 2, and remove every `// transitional: Task 5` conversion.

- [ ] **Step 4: Run all three modules**

Expected: all pass, and `grep -rn 'transitional: Task 5' .` finds nothing.

- [ ] **Step 5: Commit**

```bash
git commit -m "Use uuid.UUID for recovery code user IDs"
```

### Task 6: Passkey IDs, user handles and ceremony IDs in every module

**Files:**
- Modify: `passkey/store.go`, `passkey/passkey.go`, `passkey/http.go`, `passkey/events.go`, `passkey/*_test.go` (including `testauth_test.go`'s `storedCredential`)
- Modify: `memstore/passkey.go`, `storetest/passkey.go`
- Modify: `store/sql/{postgres,sqlite}/passkey.go`, both `schema.sql` (`passkey_credentials`: `id`, `user_id`)
- Modify: `examples/webapp/handlers_passkey.go` and its tests, and files marked `// transitional: Task 6`

**Interfaces:**
- Consumes: Task 2's helpers.
- Produces:
  - `passkey.Credential.ID`, `passkey.Credential.UserID`, `passkey.User.ID` and `passkey.Event.UserID` are `uuid.UUID`. `WebAuthnID()` returns `User.ID`'s 16 bytes.
  - `passkey.Store`: `GetCredentialsByUserID(ctx, userID uuid.UUID)`, `DeleteCredential(ctx, userID, id uuid.UUID, allowLast bool)`, `DeleteCredentialsByUserID(ctx, userID uuid.UUID)`, `RenameCredential(ctx, userID, id uuid.UUID, name string)`. `ChallengeStore` is unchanged.
  - `passkey.Service`: `BeginLogin` and `BeginDiscoverableLogin` return `(*protocol.CredentialAssertion, uuid.UUID, error)`; `FinishLogin`, `FinishLoginResponse`, `FinishDiscoverableLogin` and `FinishDiscoverableLoginResponse` take `ceremonyID uuid.UUID`; `DeleteCredential(ctx, userID, id uuid.UUID, opts DeleteOptions)`.
  - Challenge keys: `"register:" + user.ID.String()`, `"login:" + ceremonyID.String()`, `"discover:" + ceremonyID.String()`.

- [ ] **Step 1: Write the failing tests**

- `passkey.TestWebAuthnIDIsTheSixteenUUIDBytes`: `(&webauthnUser{user: &User{ID: id}}).WebAuthnID()` equals `id[:]`.
- `passkey.TestFinishDiscoverableLoginRejectsTextUserHandle`: register a credential with the test authenticator, begin a discoverable login, and forge the assertion with `userHandle: []byte(user.ID.String())` (36 bytes). `FinishDiscoverableLoginResponse` returns `errors.Is(err, ErrChallengeFailed)`.
- `passkey.TestPasskeyIDsAreVersion7`: the credential from `FinishRegistrationResponse` and the ceremony ID from `BeginLogin` both satisfy `u[6]>>4 == 7`.
- `examples/webapp.TestPasskeyLoginWithMalformedCookiesIsTreatedAsMissing`: finishing a passkey login with the user cookie and the ceremony cookie set to `not-a-uuid` gets the same response as with both cookies missing.
- `examples/webapp.TestDeletePasskeyWithMalformedIDReturns400`: posting `credential_id=not-a-uuid` with a valid CSRF token returns 400, and the user's passkeys are unchanged.

- [ ] **Step 2: Run them to verify they fail**

Run in the root: `go vet ./passkey/`. Run in `examples/webapp`: `go vet ./...`
Expected: compile errors.

- [ ] **Step 3: Implement**

Apply the Interfaces block. Replace `passkey`'s `generateID` with `uuid.NewV7()` and delete it. In discoverable login, compare `cred.UserID[:]` with the returned handle using `bytes.Equal` and return `ErrChallengeFailed` when they differ. The example app parses its passkey cookies and `credential_id` with `uuid.Parse`: a bad cookie counts as missing, a bad form value gets 400. Edit `passkey_credentials` in both schemas as in Task 2, and remove every remaining transitional conversion.

- [ ] **Step 4: Run all three modules**

Expected: all pass, and `grep -rn 'transitional:' .` finds nothing.

- [ ] **Step 5: Commit**

```bash
git commit -m "Use uuid.UUID for passkey IDs, user handles and ceremonies"
```

### Task 7: Docs

**Files:**
- Modify: `CHANGELOG.md` (under `## [Unreleased]`), `README.md`

**Interfaces:**
- Consumes: the API from Tasks 1 to 6.
- Produces: nothing.

- [ ] **Step 1: CHANGELOG**

Add `### BREAKING CHANGES` under `## [Unreleased]` with one bullet in the style of the 0.3.0 entry: every ID Sulis generates (users, sessions, tokens, TOTP and passkey credentials, passkey ceremonies) is now a version 7 `uuid.UUID` from the standard library, and `uuid.Nil` means "no ID"; the passkey user handle is the 16 ID bytes; both `store/sql` schemas store IDs as `uuid` (Postgres) or 16-byte `BLOB` (SQLite), and `tokens.user_id` is nullable. Migration: there is none; recreate existing databases.

- [ ] **Step 2: README**

Update every signature and example that shows a string ID. Where the README says IDs are "opaque identifiers sulis generated", say they are version 7 UUIDs, and that a version 7 UUID contains its creation time to the millisecond, so an ID shown to users tells when the record was created. In the passkey section, say the user handle is the 16 bytes of `User.ID`.

- [ ] **Step 3: Check**

Run: `grep -n -E '(userID|sessionID|ceremonyID|id) string' README.md`
Expected: no matches. Run the module check in all three modules, then staticcheck, gosec and govulncheck at the versions `.github/workflows/ci.yml` pins, in all three modules.
Expected: all clean.

- [ ] **Step 4: Commit**

```bash
git commit -m "Document UUID identifiers"
```

## After the plan

The release follows the v0.3.0 pattern and waits for the maintainer: one commit that closes `[Unreleased]` as `[0.4.0]` and moves `store/sql/go.mod` and `examples/webapp/go.mod` to `v0.4.0`, then the tags `v0.4.0` and `store/sql/v0.4.0`.
