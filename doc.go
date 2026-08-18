// Package sulis is a Go authentication library for consumer-owned
// persistence: password login, magic-link login, two-factor pending-login
// tokens, password reset, email verification, server-side sessions, and the
// HTTP middleware that attaches an authenticated user and session to a
// request context. The totp, passkey, and recovery subpackages add TOTP,
// WebAuthn passkeys, and recovery codes as second factors or standalone
// credentials; passwordcheck screens new passwords against known-compromised
// values.
//
// # Store-interface architecture
//
// sulis ships no database driver and stores nothing itself. Every piece of
// state it needs — users, sessions, and tokens for the root package; TOTP
// credentials, passkey credentials and their WebAuthn challenges, and
// recovery codes for the respective subpackages — is read and written
// through a small interface (UserStore, SessionStore, TokenStore, and each
// subpackage's own Store) that the consumer implements against whatever they
// already run: Postgres, SQLite, DynamoDB, or anything else. Those
// interfaces document requirements no compiler can check — ConsumeToken must
// find-and-mark a token used in one atomic step, UpdateUser must reject a
// write built from a stale read, DeleteSession must scope its delete to the
// owning user — because a store that gets one of them wrong satisfies the
// interface and still breaks the guarantee the library is built on. See
// "Store contracts" below for how to prove an implementation correct instead
// of hoping it is.
//
// # Safe by default
//
// Every default is chosen so that calling New and nothing else is already
// the secure configuration, not a starting point that still needs hardening:
// an in-process rate limiter guards password, reset, and magic-link attempts
// before any other option is set; new passwords are screened against a
// breach corpus; a new session is refused for an account whose email isn't
// verified yet, including the rotation RefreshSession would otherwise mint
// from a signup session; a WebAuthn passkey requires user verification (a PIN or a
// biometric), not bare possession of an unlocked device; cookie sessions
// carry HttpOnly, Secure, SameSite=Lax, and a __Host- name; and changing a
// password revokes every other session on the account. Every one of these
// can be turned off — WithoutRateLimiting, WithPasswordChecker(nil),
// WithRequireVerifiedEmail(false), passkey.WithUserVerification with
// protocol.VerificationDiscouraged, WithRevokeSessionsOnPasswordChange(false)
// — but each is a visible call a reviewer can find, never the silent
// consequence of forgetting one. See the README's "Operational requirements"
// section for the full list and the reasoning behind each default.
//
// # A minimal end-to-end flow
//
// Registration and login against the reference in-memory stores (package
// memstore — fine for this, tests, and local development; never
// production):
//
//	users, sessions, tokens := memstore.NewUserStore(), memstore.NewSessionStore(), memstore.NewTokenStore()
//
//	auth, err := sulis.New(users, sessions, tokens, sulis.NoSecondFactors{})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	ri := sulis.RequestInfo{IP: r.RemoteAddr}
//	user, session, rawToken, err := auth.Register(ctx, email, password, ri)
//	if err != nil {
//		return err // ErrUserAlreadyExists, ErrInvalidEmail,
//		            // ErrPasswordTooShort/TooLong, ErrPasswordCompromised, ...
//	}
//	setSessionCookie(auth.SessionCookie(rawToken, session.ExpiresAt))
//
//	// Later, on a login request:
//	result, err := auth.Login(ctx, email, password, ri)
//	if err != nil {
//		return err // ErrInvalidCredentials, ErrRateLimited, ErrEmailNotVerified, ...
//	}
//	if result.NeedsSecondFactor {
//		// No session exists yet — see CompleteTwoFactor and the totp,
//		// passkey, and recovery subpackages.
//		return promptForSecondFactor(result.User, result.PendingToken)
//	}
//	setSessionCookie(auth.SessionCookie(result.SessionToken, result.Session.ExpiresAt))
//
// A NoSecondFactors application still gets rate limiting, password
// screening, email-verification gating, and hashed everything for free; a
// real SecondFactorChecker implementation (backed by totp.Store,
// passkey.Store, or both) is what turns the NeedsSecondFactor branch above
// from dead code into two-factor authentication. See package example tests
// for compiler-checked walkthroughs of password login with a second factor,
// magic links, passkeys, password reset, and email change.
//
// # Store contracts
//
// Every store interface's doc comment states its atomicity, scoping, and
// error-sentinel requirements; the README's "Store Contracts" section
// collects them with reference SQL. Package storetest turns those contracts
// into an executable conformance suite — supported public API and the
// intended integration path, not an internal test helper:
//
//	func TestMyUserStore(t *testing.T) {
//		storetest.RunUserStore(t, func() sulis.UserStore { return newMyUserStore(t) })
//	}
//
// Package memstore is a reference implementation of every interface in this
// module (root and subpackages), written to be read end to end and proven,
// by that same suite, to satisfy every contract it documents.
//
// # Security events
//
// EventKind's constants (events.go) are a closed, dot-namespaced taxonomy of
// this root package's own security-relevant decisions — a password refused,
// a second factor demanded, a session issued or expired, a limiter tripped,
// an account disabled, and more. WithEventSink wires a sink through;
// NewSlogSink adapts a *slog.Logger in one line. See Event's doc comment for
// what a reported event may and may not contain.
//
// The totp and passkey subpackages have no event sink of their own; wiring
// one through them is a separate piece of work (see the T509 Decisions row
// in PROGRESS.md). recovery does: its own independent EventKind, Event,
// EventSink, and WithEventSink (recovery/events.go), deliberately not
// wire-compatible with the root taxonomy — see recovery.EventSink's doc
// comment for why. An application wanting one unified event stream writes
// a small adapter translating a recovery.Event into whatever shape its own
// sink expects.
//
// # Where to go next
//
// The README documents every flow (password reset, magic link, two-factor,
// email verification, step-up re-authentication, cookie sessions and CSRF,
// security events) at the depth a doc comment can't. SECURITY.md covers how
// to report a vulnerability and the supported-version policy;
// docs/threat-model.md names the in-scope threats, the shipped mitigation for
// each, what's explicitly out of scope, and the residual risks — such as the
// default rate limiter being per-process rather than shared across
// instances — that remain the deploying application's to manage.
package sulis
