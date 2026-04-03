# Password API Split Design

## Goal

Make the password API explicit by separating "change an existing password" from "set the first password on a passwordless account."

## Problem

`ChangePassword` currently does two different jobs:

1. verify the current password and replace it for password-based users
2. bootstrap an initial password for passwordless users when `oldPassword == ""`

That overload makes the method harder to reason about and weakens the meaning of its name. The caller has to know hidden branching rules instead of choosing an API that matches the intended authorization flow.

## Approved Direction

This change is a strict API split with no compatibility shim.

- `ChangePassword(ctx, userID, oldPassword, newPassword)` becomes strict again.
- Add `SetInitialPassword(ctx, userID, newPassword)` for passwordless users only.
- Remove the passwordless bootstrap path from `ChangePassword`.

This is an intentional breaking change in favor of clearer semantics.

## Public API

### `ChangePassword`

`ChangePassword` will only support users who already have a password hash.

Behavior:
- load the user
- reject passwordless users
- verify `oldPassword` against the stored hash
- hash `newPassword`
- update the user record

Contract:
- this method means "prove you know the current password, then change it"
- it no longer doubles as a bootstrap path for passwordless accounts

### `SetInitialPassword`

Add a new method:

```go
func (s *Sulis) SetInitialPassword(ctx context.Context, userID, newPassword string) error
```

Behavior:
- load the user
- require that `PasswordHash == ""`
- hash `newPassword`
- update the user record

Contract:
- this method means "this account is passwordless and is now being given its first password"
- authorization remains the application's responsibility; callers should only expose this after an authenticated flow such as a valid magic-link or passkey session

## Error Handling

Keep the error changes minimal.

- `ChangePassword` returns `ErrInvalidCredentials` when called for a passwordless user or when the old password is wrong.
- `SetInitialPassword` returns `ErrInvalidCredentials` when called for a user that already has a password set.
- existing user lookup and hashing failures continue to propagate the same way they do now.

This keeps the patch small while still making the method boundary explicit.

## Implementation Shape

Use two public methods with a small shared helper for writing the new password hash so the behavior stays DRY without reintroducing API ambiguity.

Expected file changes:
- `sulis.go`
- `sulis_test.go`
- `README.md`

No store interfaces need to change.

## Tests

Update root-package tests to cover:

1. `ChangePassword` still works for password-based users
2. `ChangePassword` rejects passwordless users
3. `SetInitialPassword` succeeds for passwordless users
4. `SetInitialPassword` rejects users that already have a password
5. login succeeds with the new password after `SetInitialPassword`

The tests should remove the now-invalid assumption that `ChangePassword(..., "", newPassword)` is a supported bootstrap path.

## Documentation

Update `README.md` so it clearly states:

- `Register` is the password-first signup path
- magic-link flows may create passwordless users
- `ChangePassword` is for existing password-based accounts
- `SetInitialPassword` is the explicit bootstrap path for passwordless accounts

## Migration Note

Callers that currently use:

```go
s.ChangePassword(ctx, userID, "", newPassword)
```

must switch to:

```go
s.SetInitialPassword(ctx, userID, newPassword)
```

## Non-Goals

- no new store interfaces
- no session or token flow redesign
- no library-enforced policy for when bootstrap is allowed; that remains application-level authorization
