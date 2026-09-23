# Sulis Example Web App

A runnable example that wires the sulis authentication library end to end
against a local SQLite database. It is living documentation: every page
names, in its footer, which library calls it just made.

## Run

    cd examples/webapp
    go run .

The server listens on `:8443` over HTTPS with a self-signed certificate
generated at startup. Your browser will warn about the certificate; accept
it to continue.

## Flags

- `-addr`: address to listen on (default `:8443`)
- `-db`: path to the SQLite database file (default `webapp.db`)
- `-tls`: serve over TLS with a self-signed certificate (default `true`)

## Why `-tls` defaults to true

Safari refuses to store a `Secure` cookie over plain HTTP, even on
localhost. sulis's session and CSRF cookies are always `Secure` (see the
library's `SessionCookie` doc comment), so on Safari a plain-HTTP run of
this app would issue cookies the browser silently drops, and every request
after login would look logged out. Chrome and Firefox are more lenient
about `Secure` on localhost, so `-tls=false` works there if you don't want
to click through a self-signed certificate warning. Safari users should
leave `-tls` at its default.

## Page-to-library-call map

Every page's own footer names the exact calls it makes; this table is the
same information gathered in one place.

| Page | Route | Library calls |
|---|---|---|
| Home | `GET /` | none |
| Register | `GET/POST /register` | `sulis.MemoryLimiter.Allow`, `sulis.Register`, `sulis.IssueCSRFToken`, `sulis.CreateEmailVerificationToken` |
| Verify email | `GET /verify` | `sulis.VerifyEmail` |
| Log in | `GET/POST /login` | `sulis.Login`, `sulis.IssueCSRFToken`, `sulis.MemoryLimiter.Allow` (resend), `passkey.Service.BeginLogin`, `passkey.Service.FinishLoginResponse`, `passkey.Service.BeginDiscoverableLogin`, `passkey.Service.FinishDiscoverableLoginResponse`, `sulis.IssueSessionUnchecked` |
| Second factor | `GET/POST /login/second-factor` | `totp.Service.Validate`, `recovery.Service.Consume`, `sulis.CompleteTwoFactor` |
| Account | `GET /account` | `sulis.ListUserSessions`, `sulis.RevokeSession`, `sulis.IssueCSRFToken` |
| Change email | `GET/POST /account/email` | `sulis.RequireRecentAuth`, `sulis.ChangeEmail`, `sulis.ConfirmEmailChange` |
| Security | `GET /security` | `totp.Service.Enroll`/`Unenroll`, `recovery.Service.Generate`/`Remaining`/`Disable`, `passkey.Service.BeginRegistration`, `passkey.Service.FinishRegistrationResponse`, `passkey.Service.DeleteCredential`, `sulis.RequireRecentAuth` (guards every action on the page) |
| Re-authenticate | `GET/POST /reauth` | `sulis.RequireRecentAuth`, `sulis.ReAuthenticate` |
| Forgot password | `GET/POST /forgot` | `sulis.CreatePasswordResetToken` |
| Reset password | `GET/POST /reset` | `sulis.ResetPassword` |
| Magic link | `GET/POST /magic`, `GET /magic/redeem` | `sulis.CreateMagicLinkToken`, `sulis.RedeemMagicLink` |
| Dev mailbox | `GET /dev/mailbox` | none (reads the demo's own outbox) |

The passkey JSON endpoints under `/api/passkeys/...` (used by
`static/passkeys.js`, not visited directly) are documented in
`handlers_passkey.go`.

## Manual passkey walkthrough

Passkey registration and sign-in need a real authenticator (a platform one,
like Touch ID/Windows Hello, or a security key), so they are not covered by
the automated tests. Walk through them by hand:

1. Register an account and verify its email (follow the link in
   `/dev/mailbox`), then log in with your password.
2. Go to `/security` and click **Register a passkey**. Your browser will
   prompt for an authenticator; complete it. The new passkey now appears in
   the list on that page.
3. Click **Log out** on `/account`.
4. On `/login`, type the same account's email and click **Sign in with a
   passkey**. Complete the authenticator prompt; you land back on
   `/account` with no password entered.
5. Log out again, and this time click **Sign in without a username** with
   the email field left empty. Your authenticator itself supplies which
   account to sign in as (this only works for a passkey registered as
   discoverable, which is the default here).

## Step-up authentication

Every action that changes how you can get back into the account calls
`sulis.RequireRecentAuth` before doing anything, requiring the session's
last proven authentication to be within 5 minutes: changing your email
address, enrolling or disabling an authenticator app, generating new
recovery codes, and registering or removing a passkey. An older session is
redirected to `/reauth`, which asks for your password again
(`sulis.ReAuthenticate`) and, on success, sends you back to finish what you
were doing.

Registering a passkey is the one exception to that redirect, because it
starts with a `fetch()` call rather than a form post: a redirect there would
hand JavaScript an HTML login page instead of something it can read. It
answers `403` with `{"error": "recent authentication required"}` instead,
and `static/passkeys.js` shows a message pointing at `/reauth`. A real
application would open an inline re-authentication prompt at that point and
retry the ceremony once the password is proven, rather than making the user
navigate away and start over.

## Confirming an email change notifies the old address

`sulis.ConfirmEmailChange` returns the user with the new address already in
place, so the old one is gone from the database by the time the handler
runs. This app therefore remembers the old address itself when the change is
staged, keyed by a hash of the confirmation token (see `mailbox.go`), and
mails it a "Your email address was changed" notice once the change goes
through. That address is the one an attacker taking over the account does
not control, which is exactly why it is worth telling.

## Rate limiting

One `sulis.MemoryLimiter` is shared across the app. sulis's own service
builds its default limiter for the flows it owns (login, password reset,
magic link); this second instance is passed to `totp.WithLimiter` and
`recovery.WithLimiter`, and the register and verification-resend handlers
call it directly under the `register:` and `resend:` key prefixes, budgeted
in `newApp`.

## Security events

sulis and `passkey` each declare their own event type and neither imports
the other, so joining them into one log stream is the application's job:
one small adapter per module at the wiring boundary. `newApp` uses
`sulis.NewSlogSink` for the root package's events and the equivalent
adapter in `events.go` for the passkey package's, so both land in the same
`*slog.Logger`.

## `/dev/mailbox` is unauthenticated and dev-only

`/dev/mailbox` lists every email this demo has "sent" (verification links,
password resets, magic links, email-change confirmations) in place of a
real mail transport, and it requires no login to view. That is fine here
because the outbox only ever holds this demo's own test traffic, but the
pattern does not belong in anything real: if you adapt this example, either
delete this route and its handler or put a real authentication and
authorization check in front of it before it can see live mail.
