# Example Web App Design

## Goal

Ship one complete, runnable demo web app that wires sulis the way a real
application should. It is living documentation and an integration proof for
the whole library. This closes the last open TODOS.md item
("production-style integration example").

## Approved Decisions

- Lives at `examples/webapp/`, its own Go module with `replace` directives
  pointing at the local library modules (root and `store/sql`).
- Database: SQLite via `store/sql/sqlite`. One command to run, no setup.
- Coverage: everything. Register with email verification, password login,
  password reset, magic link, TOTP enrollment and login, recovery codes,
  passkeys (including usernameless login), step-up re-authentication,
  change email, logout and session list.
- Server-rendered HTML with `html/template`. One small plain JavaScript
  file, only for the WebAuthn browser calls.
- No email server. Outbound mail is captured in memory, printed to the
  console, and shown on a dev-only "mailbox" page.
- Rate limiting with the library's own `MemoryLimiter`. CSRF with the
  library's `IssueCSRFToken` / `RequireCSRFToken` / `RequireSameOrigin`.
- Auth events go to `slog` through an `EventSink` adapter.
- A `-tls` flag generates a self-signed certificate at startup, because
  Safari needs HTTPS for Secure cookies (see README "Local development").

## Architecture

A single `main` package, split by flow so each file reads on its own:

- `main.go`: flags (`-addr`, `-tls`, `-db`), store construction and
  migration, `sulis.New` wiring with limiter, password checker, event
  sink, and cookie options; totp, passkey, and recovery service
  construction; background cleanup loop for expired sessions and tokens;
  route table; graceful shutdown.
- `handlers_account.go`: register, verify email, login (with the 2FA
  branch), logout, password reset, change email, session list and revoke.
- `handlers_mfa.go`: TOTP enroll, confirm, validate; recovery code
  generation and use; step-up re-authentication for sensitive pages.
- `handlers_passkey.go`: JSON endpoints for the four WebAuthn ceremonies,
  including usernameless login, plus credential list and delete.
- `mailbox.go`: in-memory outbox implementing the app's mail interface;
  `/dev/mailbox` page lists captured messages and their links.
- `events.go`: adapters from the root and passkey event types to `slog`,
  demonstrating the per-package adapter pattern.
- `tls.go`: self-signed certificate generation for `-tls`.
- `templates/`: one base layout plus one template per page.
- `static/passkeys.js`: WebAuthn create/get calls and base64url helpers.
- `README.md`: how to run, what to click, and a map from each page to the
  library calls behind it.

The app follows every operational requirement the main README lists:
limiter wired, cleanup scheduled, CSRF on all state-changing routes,
cookies through the library's cookie helpers, TLS note honored.

## Data Flow Example (login)

Form POST → CSRF check → limiter-guarded `VerifyPassword` → if the user
has second factors, create a two-factor token and render the challenge
page (TOTP code, recovery code, or passkey) → `CompleteTwoFactor` →
session cookie set via the library helper → redirect to the account page.
Every page states, in a small footer, which library calls it just made,
so the demo teaches while it runs.

## Error Handling

Handlers map library sentinel errors to user-facing messages without
leaking detail (for example, `ErrInvalidCredentials` and rate-limit
rejections both render generic text). Unexpected errors log with `slog`
and render a plain 500 page. The dev mailbox and the event log make the
hidden detail visible to the developer instead.

## Testing

- `webapp_test.go`: end-to-end tests over `httptest` covering register →
  verify → login, password reset, magic link, TOTP enroll → 2FA login,
  recovery code login, change email, step-up, and logout. Tests drive the
  real handlers with the real SQLite store (temp file or in-memory DSN).
- Passkey ceremonies need a real browser authenticator, so tests cover the
  endpoints' error paths only; the happy path is a documented manual step.
- CI runs `go test ./...` and `go vet ./...` inside `examples/webapp` next
  to the existing module entries.

## Non-Goals

- No account admin UI, no user roles, no profile fields beyond email.
- No real email delivery, no HTML mail.
- No JavaScript framework, no build step, no CSS framework (one small
  hand-written stylesheet).
- No Docker or deployment manifests.
- Not a template to fork wholesale; it is documentation that compiles.
