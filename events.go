package sulis

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Security events.
//
// Every security-relevant decision this package makes — a password refused, a
// second factor demanded, a session issued or expired, a limiter tripped, an
// account disabled — is reported to the EventSink configured with
// WithEventSink. Without that option nothing is emitted and nothing is
// allocated: the default sink is nil, and every emission site is a nil check
// away from doing nothing at all.
//
// That second half is a real constraint on how emissions are written, not a
// hopeful description. Arguments are evaluated before a call, so an event's
// Metadata map must NOT be built at the call site — it would be allocated on
// every decision whether or not anybody was listening. emit takes variadic
// key/value labels and builds the map after its nil check instead, and
// TestNilSinkPathAllocatesNothing (events_test.go) holds the claim to
// account with testing.AllocsPerRun.
//
// # The no-secrets rule
//
// No event ever carries credential material. There is deliberately no field
// on Event that could hold one: no token, no password, no hash, no nonce.
// Beyond that, this package never copies ANY caller-supplied string into an
// event except the RequestInfo the caller explicitly passed for this purpose.
// In particular an event never carries:
//
//   - a raw password, session token, reset/magic-link/two-factor/email
//     token, or magic-link binding nonce;
//   - a stored password hash or session token hash;
//   - the submitted email address (people type passwords into the email
//     field, and an event taxonomy that copies caller input is one bad day
//     away from being a credential log);
//   - the operator-supplied reason passed to DisableUser, for the same
//     reason.
//
// Accounts are identified by UserID, sessions by SessionID. Both are opaque
// identifiers this package generated; neither authenticates anything on its
// own (see SessionStore.DeleteSession for why knowing a session ID is not
// enough to act on it). The rule is enforced by test, not only by
// convention — see TestNoEventCarriesSecretMaterial in events_test.go, which
// drives every emitting flow and scans every field of every emitted event
// for every secret those flows were fed.
//
// # Best effort, after the fact
//
// EventSink.Emit returns nothing, so a sink cannot fail a flow: there is no
// error for a caller to propagate and none to ignore. Emissions happen AFTER
// the decision they report, never before, so an event is a record of what
// already happened rather than an announcement of what is about to. A sink
// that panics is contained (the panic is recovered and dropped) for the same
// reason: an observability hook must not be able to deny authentication to
// everybody. Do not rely on that containment — a sink should hand the event
// to a channel, a logger, or a buffer and return, doing anything slow or
// failure-prone somewhere else. Emit runs on the caller's goroutine and
// inside the caller's latency budget.
//
// # Scope
//
// The taxonomy covers the root package's flows. The totp, passkey, and
// recovery subpackages have their own services and their own stores and do
// NOT emit events; wiring a sink through them is a separate piece of work
// (see the T509 Decisions row in PROGRESS.md).

// EventKind names one security-relevant decision. The values are stable,
// lowercase, dot-namespaced strings safe to use as log field values, metric
// labels, or database enum entries.
//
// Each constant repeats the EventKind type deliberately, rather than
// leaning on a const block carrying the type down the list: the
// completeness test (TestEveryDeclaredEventKindIsEmitted) reads them out of
// this file's source, so every declaration has to look the same.
type EventKind string

const (
	// EventAccountRegistered reports that Register created an account.
	EventAccountRegistered EventKind = "account.registered"

	// EventLoginSucceeded reports that a password verified — VerifyPassword
	// completed, including its account-status and lockout checks. It does
	// NOT mean a session exists: a user with an enrolled second factor gets
	// EventSecondFactorDemanded next, and only EventSessionIssued means a
	// session was actually minted. Carries MetaMethod.
	EventLoginSucceeded EventKind = "login.succeeded"

	// EventLoginFailed reports that an authentication attempt was refused —
	// a wrong or missing credential, or a gate (disabled, locked,
	// unverified email, an unavailable second-factor checker) refusing an
	// otherwise-correct one. Carries MetaReason and MetaMethod. UserID is
	// empty when the address matched no account.
	EventLoginFailed EventKind = "login.failed"

	// EventPasswordChanged reports a successful ChangePassword.
	EventPasswordChanged EventKind = "password.changed"

	// EventPasswordSet reports a successful SetInitialPassword — a
	// previously passwordless account gaining its first password.
	EventPasswordSet EventKind = "password.set"

	// EventPasswordResetRequested reports that CreatePasswordResetToken (or
	// CreatePasswordResetTokenStrict) issued a reset token. The
	// unknown-address branch emits nothing: it changes no state, and an
	// event there would be a server-side record of addresses that do not
	// exist. Reset flooding is visible through EventRateLimitTripped on the
	// "reset" scope instead.
	EventPasswordResetRequested EventKind = "password.reset_requested"

	// EventPasswordReset reports a successful ResetPassword.
	EventPasswordReset EventKind = "password.reset"

	// EventPasswordRehashed reports that a stored hash was upgraded on a
	// successful verification — because it was weaker than the configured
	// Argon2Params, or because it predated NFKC normalization. This is what
	// makes "did raising Argon2Params actually reach the installed base?"
	// an answerable question.
	EventPasswordRehashed EventKind = "password.rehashed"

	// EventPasswordRehashFailed reports that such an upgrade was attempted
	// and did not land. The login itself succeeded regardless — the upgrade
	// is best effort and its failure is deliberately swallowed (see
	// rehashPassword) — so this event is the only trace it left. Carries
	// MetaReason: ReasonHashFailed, ReasonStoreFailed, or
	// ReasonPasswordChanged.
	EventPasswordRehashFailed EventKind = "password.rehash_failed"

	// EventPasswordLegacyFormMatched reports that a password verified only
	// through verifyPassword's pre-NFKC compatibility fallback: the stored
	// hash was written before normalization existed. It is followed by an
	// EventPasswordRehashed (or EventPasswordRehashFailed) for the same
	// account, because matching that way is exactly the moment to migrate
	// the hash.
	//
	// This event is what makes retiring that fallback answerable: when it
	// stops appearing for a deployment, every account has been migrated and
	// the fallback can go. Without it the fallback would have to stay
	// forever on the grounds that nobody can prove it is unused.
	EventPasswordLegacyFormMatched EventKind = "password.legacy_form_matched"

	// EventSecondFactorDemanded reports that a verified first factor earned
	// a pending token rather than a session, because the account has a
	// second factor enrolled. Also emitted by CreateTwoFactorToken.
	EventSecondFactorDemanded EventKind = "twofactor.demanded"

	// EventSecondFactorCompleted reports a successful CompleteTwoFactor.
	EventSecondFactorCompleted EventKind = "twofactor.completed"

	// EventSecondFactorFailed reports that CompleteTwoFactor refused —
	// an unknown, expired, already-used, or wrong-purpose pending token, a
	// token belonging to a different user, or a gate refusing the account.
	// Carries MetaReason.
	EventSecondFactorFailed EventKind = "twofactor.failed"

	// EventSessionIssued reports that a session row was created, by any
	// path: Register, Login, a redeemed magic link, CompleteTwoFactor,
	// IssueSession, or IssueSessionUnchecked. Carries MetaMethod and the
	// new session's SessionID. This is the method-agnostic "somebody is now
	// signed in" signal.
	EventSessionIssued EventKind = "session.issued"

	// EventSessionRevoked reports a successful RevokeSession (MetaScope
	// ScopeSingleSession, with SessionID set) or RevokeAllSessions
	// (MetaScope ScopeAllSessions, with SessionID empty).
	EventSessionRevoked EventKind = "session.revoked"

	// EventSessionRefreshed reports a successful RefreshSession. SessionID
	// is the NEW session's ID — RefreshSession mints a new row rather than
	// rewriting the old one.
	EventSessionRefreshed EventKind = "session.refreshed"

	// EventSessionExpired reports that ValidateSession rejected and deleted
	// a session past its absolute ExpiresAt.
	EventSessionExpired EventKind = "session.expired"

	// EventSessionIdleExpired reports that ValidateSession rejected and
	// deleted a session past its IdleExpiresAt — the idle timeout
	// configured by WithIdleTimeout, checked before absolute expiry.
	EventSessionIdleExpired EventKind = "session.idle_expired"

	// EventEmailChangeStaged reports that ChangeEmail staged a new address
	// and issued a confirmation token. The address itself is not in the
	// event; see the no-secrets rule above.
	EventEmailChangeStaged EventKind = "email.change_staged"

	// EventEmailChangeConfirmed reports that ConfirmEmailChange made a
	// staged address live, revoking the account's sessions in the process.
	EventEmailChangeConfirmed EventKind = "email.change_confirmed"

	// EventEmailVerified reports that an address was verified for the first
	// time, by VerifyEmail or by a redeemed magic link. The idempotent
	// re-verification of an already-verified address emits nothing, because
	// nothing was decided.
	EventEmailVerified EventKind = "email.verified"

	// EventMagicLinkCreated reports that CreateMagicLinkToken issued a
	// link. UserID is empty when the address has no account yet — the user
	// is created at redemption.
	EventMagicLinkCreated EventKind = "magiclink.created"

	// EventMagicLinkRedeemed reports that a magic-link token was consumed
	// and, when binding is enabled, matched its binding nonce. It is the
	// magic-link counterpart of EventLoginSucceeded: proof of mailbox
	// control, not proof that a session followed.
	EventMagicLinkRedeemed EventKind = "magiclink.redeemed"

	// EventMagicLinkRejected reports that RedeemMagicLink refused — an
	// unknown, expired or already-used token, or a missing or wrong binding
	// nonce. Carries MetaReason. A ReasonBindingMismatch here is the
	// signal that a link was clicked somewhere other than the browser that
	// asked for it: forwarded, prefetched, or stolen.
	EventMagicLinkRejected EventKind = "magiclink.rejected"

	// EventRateLimitTripped reports that the configured Limiter denied a
	// key. Carries MetaScope (the choke point: "password", "reset",
	// "magic") and MetaDimension (DimensionAccount or DimensionIP). The
	// limiter key itself is never in the event — it embeds an email
	// address.
	EventRateLimitTripped EventKind = "ratelimit.tripped"

	// EventAccountDisabled reports a successful DisableUser. The
	// operator-supplied reason is deliberately not carried.
	EventAccountDisabled EventKind = "account.disabled"

	// EventAccountEnabled reports a successful EnableUser.
	EventAccountEnabled EventKind = "account.enabled"

	// EventAccountLocked reports that the optional automatic lockout (see
	// WithFailureLockout) set or extended a LockedUntil deadline after a
	// failed password attempt.
	EventAccountLocked EventKind = "account.locked"

	// EventAccountLockoutCleared reports that a correct password outside
	// any active lockout window cleared the stale failure count and
	// deadline.
	EventAccountLockoutCleared EventKind = "account.lockout_cleared"

	// EventReauthSucceeded reports a successful ReAuthenticate — the
	// step-up gate RequireRecentAuth checks was refreshed.
	EventReauthSucceeded EventKind = "reauth.succeeded"

	// EventReauthFailed reports that ReAuthenticate refused. Carries
	// MetaReason. A burst of these against one session is a stolen-cookie
	// signal: whoever holds the session does not know the password.
	EventReauthFailed EventKind = "reauth.failed"

	// EventCSRFRejected reports that (*Sulis).RequireCSRFToken's
	// double-submit check refused a state-changing request. Emitted only by
	// the Sulis-bound middleware; the package-level RequireCSRFToken has no
	// sink to emit to.
	EventCSRFRejected EventKind = "csrf.rejected"

	// EventSameOriginRejected reports that (*Sulis).RequireSameOrigin
	// refused a state-changing request as cross-site (ReasonCrossSite, from
	// Sec-Fetch-Site) or as carrying an unlisted Origin
	// (ReasonOriginNotAllowed). Emitted only by the Sulis-bound middleware;
	// the package-level RequireSameOrigin has no sink to emit to.
	EventSameOriginRejected EventKind = "sameorigin.rejected"
)

// MetadataKey is a key in Event.Metadata. The set is closed — these four
// constants are the only keys this package ever writes — so a sink can index
// on them without pattern-matching free-form strings, and a reviewer can see
// at a glance everything an event can say beyond its kind.
type MetadataKey string

const (
	// MetaReason says why a decision went the way it did. Its value is
	// always one of the Reason constants below: a fixed label chosen by
	// this package, never caller input and never an error string.
	MetaReason MetadataKey = "reason"

	// MetaMethod is an AuthMethod value — which credential is involved.
	MetaMethod MetadataKey = "method"

	// MetaScope narrows the kind. On EventSessionRevoked it is
	// ScopeSingleSession or ScopeAllSessions; on EventRateLimitTripped it
	// is the choke point whose budget was exhausted ("password", "reset",
	// "magic").
	MetaScope MetadataKey = "scope"

	// MetaDimension is DimensionAccount or DimensionIP, on
	// EventRateLimitTripped: which of the limiter's two keys denied. The
	// distinction is the whole reason both keys exist — one account being
	// guessed is a different incident from one host spraying many
	// accounts.
	MetaDimension MetadataKey = "dimension"
)

// Reason labels, the closed set of values MetaReason can carry. They are
// fixed strings chosen by this package: never an error message, never
// anything a caller supplied.
const (
	ReasonUserNotFound      = "user_not_found"
	ReasonNoPassword        = "no_password"
	ReasonWrongPassword     = "wrong_password"
	ReasonAccountDisabled   = "account_disabled"
	ReasonAccountLocked     = "account_locked"
	ReasonEmailNotVerified  = "email_not_verified"
	ReasonFactorCheckFailed = "factor_check_failed"
	ReasonTokenInvalid      = "token_invalid"
	ReasonTokenExpired      = "token_expired"
	ReasonTokenAlreadyUsed  = "token_already_used"
	ReasonUserMismatch      = "user_mismatch"
	ReasonBindingMismatch   = "binding_mismatch"
	ReasonHashFailed        = "hash_failed"
	ReasonStoreFailed       = "store_failed"
	ReasonPasswordChanged   = "password_changed"
	ReasonIdleTimeout       = "idle_timeout"
	ReasonAbsoluteExpiry    = "absolute_expiry"
	ReasonCSRFTokenInvalid  = "csrf_token_invalid" // #nosec G101 -- a reason label, not a credential
	ReasonCrossSite         = "cross_site"
	ReasonOriginNotAllowed  = "origin_not_allowed"
)

// Values for MetaScope on EventSessionRevoked.
const (
	ScopeSingleSession = "single"
	ScopeAllSessions   = "all"
)

// Values for MetaDimension on EventRateLimitTripped.
const (
	DimensionAccount = "account"
	DimensionIP      = "ip"
)

// Event is one security-relevant decision, as reported to an EventSink.
//
// Every field is either an identifier this package generated, a timestamp, a
// RequestInfo the caller explicitly supplied, or a label drawn from the
// closed sets above. There is deliberately no field that could carry
// credential material — see the no-secrets rule in this file's leading
// comment.
type Event struct {
	// Kind is which decision this is. Always set.
	Kind EventKind

	// UserID is the account the decision concerns, when one is known.
	// Empty for decisions made before an account is identified (a login for
	// an unknown address, a magic link for an address with no account yet,
	// a rejected pending token) and for the HTTP middleware rejections,
	// which happen before any session is validated.
	UserID string

	// SessionID is the session the decision concerns, when one is
	// relevant: the session issued, revoked, refreshed, expired, or
	// re-authenticated. Empty otherwise. It is the session's row ID, never
	// its token or the hash of its token.
	SessionID string

	// RequestInfo is what the calling application reported about the
	// request, passed straight through from the flow's own RequestInfo
	// argument. Flows that take no RequestInfo leave it zero. The one
	// exception is the HTTP middleware ((*Sulis).RequireCSRFToken and
	// (*Sulis).RequireSameOrigin), which has an *http.Request in hand and
	// fills in the transport peer address and User-Agent itself — see
	// requestInfoFromRequest for why that address is the direct peer and
	// not an X-Forwarded-For-resolved client.
	RequestInfo RequestInfo

	// At is when the decision was made, stamped at emission.
	At time.Time

	// Metadata carries the narrow, fixed labels listed under MetadataKey —
	// a reason, an auth method, a scope, a dimension. Nil when the kind
	// says everything there is to say. It is never a place to put payloads,
	// caller input, or error text.
	Metadata map[MetadataKey]string
}

// EventSink receives security events.
//
// Emit returns nothing on purpose: a sink has no way to fail a flow, so
// there is no error for this package to propagate and no temptation to
// propagate one. Implementations must be safe for concurrent use — Emit is
// called from whatever goroutine is running the flow — and should return
// quickly, doing anything slow or fallible elsewhere. Emit is called AFTER
// the decision it reports.
type EventSink interface {
	Emit(ctx context.Context, e Event)
}

// WithEventSink routes security events to sink. The default is nil: no sink,
// no events, and nothing on any flow's hot path but a nil check.
//
// The one-line wiring for an application that already has a *slog.Logger:
//
//	auth, err := sulis.New(users, sessions, tokens, factors,
//	    sulis.WithEventSink(sulis.NewSlogSink(logger)))
//
// See this file's leading comment for what an event may and may not contain,
// and EventKind's constants for the taxonomy.
func WithEventSink(sink EventSink) Option {
	return func(c *Config) { c.EventSink = sink }
}

// emit delivers e to the configured sink, if there is one. It is the only
// way this package produces an event.
//
// metaPairs is alternating key/value strings, from which emit builds
// e.Metadata — AFTER the nil-sink check, which is the whole reason it is a
// variadic parameter rather than a map the caller builds and passes in.
// A map built at the call site would be allocated whether or not anybody is
// listening, since the argument is evaluated before the call; the pairs are
// a variadic slice escape analysis can keep on the stack, because emit
// copies the strings out of it and never retains the slice itself. Call
// sites must therefore leave e.Metadata zero and pass their labels here.
// An odd trailing argument is a programming error in this package and is
// dropped rather than panicking a flow over an observability detail.
//
// Everything about it is best effort. The nil-sink check comes first, so an
// unconfigured Sulis pays one comparison and nothing else — no map, no
// timestamp, no deferred call, nothing on the heap. That claim is checked,
// not asserted: TestNilSinkPathAllocatesNothing (events_test.go) drives the
// emitting flows through testing.AllocsPerRun with no sink configured. A
// sink that panics is contained rather than allowed to unwind the flow that
// emitted: an observability hook must not be able to deny authentication.
// That containment is a backstop for a buggy sink, not a licence to write
// one — a recovered panic here is silent, because there is nowhere left to
// report it to.
//
// s may be nil: the package-level middleware helpers share their
// implementation with the Sulis-bound ones and pass a nil *Sulis to mean
// "no events".
func (s *Sulis) emit(ctx context.Context, e Event, metaPairs ...string) {
	if s == nil || s.cfg.EventSink == nil {
		return
	}
	if len(metaPairs) >= 2 {
		m := make(map[MetadataKey]string, len(metaPairs)/2)
		for i := 0; i+1 < len(metaPairs); i += 2 {
			m[MetadataKey(metaPairs[i])] = metaPairs[i+1]
		}
		e.Metadata = m
	}
	if e.At.IsZero() {
		e.At = time.Now()
	}
	defer func() { _ = recover() }()
	s.cfg.EventSink.Emit(ctx, e)
}

// gateReason maps the verdict of the two gates every session-issuing path
// runs — accountStatus and requireVerifiedEmail — onto a MetaReason label.
// An error from neither returns "", and the caller then omits the key rather
// than inventing a label for something it does not recognise.
func gateReason(err error) string {
	switch {
	case errors.Is(err, ErrAccountDisabled):
		return ReasonAccountDisabled
	case errors.Is(err, ErrAccountLocked):
		return ReasonAccountLocked
	case errors.Is(err, ErrEmailNotVerified):
		return ReasonEmailNotVerified
	default:
		return ""
	}
}

// tokenReason maps a consumeToken failure onto a MetaReason label. Anything
// that is not specifically an expiry or a replay is reported as invalid,
// matching the deliberate coarseness of the errors these flows return to
// their callers.
func tokenReason(err error) string {
	switch {
	case errors.Is(err, ErrTokenExpired):
		return ReasonTokenExpired
	case errors.Is(err, ErrTokenAlreadyUsed):
		return ReasonTokenAlreadyUsed
	default:
		return ReasonTokenInvalid
	}
}

// limiterKeyParts splits a limiter key into the labels
// EventRateLimitTripped reports. Every key this package builds is
// "<scope>:<account>" or "<scope>:ip:<address>" (see allow's callers and
// allowIP), so the scope is everything before the first colon and the
// dimension is decided by the ":ip:" marker.
//
// Only these two derived labels reach the event. The key itself never does:
// its account form embeds an email address.
func limiterKeyParts(key string) (scope, dimension string) {
	scope, _, _ = strings.Cut(key, ":")
	if strings.Contains(key, ":ip:") {
		return scope, DimensionIP
	}
	return scope, DimensionAccount
}

// requestInfoFromRequest derives the RequestInfo for an event emitted by the
// HTTP middleware, which has an *http.Request in hand and no caller-supplied
// RequestInfo to pass through.
//
// IP is the TRANSPORT PEER — the host half of r.RemoteAddr. Behind a reverse
// proxy or load balancer that is the proxy, not the end client: this package
// deliberately does not read X-Forwarded-For or any other hop header, since
// which of them to trust, and how many hops to skip, is a deployment fact no
// library can know and getting it wrong means trusting an attacker-supplied
// address. Every other flow takes its RequestInfo as an explicit argument
// for exactly that reason (see the Ratified API); this is the one place with
// no argument to take.
func requestInfoFromRequest(r *http.Request) RequestInfo {
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	return RequestInfo{IP: ip, UserAgent: r.UserAgent()}
}

// NewSlogSink adapts a *slog.Logger to EventSink, so wiring security events
// into an application that already logs structurally is one line:
//
//	sulis.WithEventSink(sulis.NewSlogSink(logger))
//
// Every event is logged at slog.LevelInfo with the message "sulis security
// event" and one attribute per populated field: kind, user_id, session_id,
// ip, user_agent, at, and one per Metadata entry (reason, method, scope,
// dimension). Empty fields are omitted rather than logged as "". Metadata
// attributes are emitted in sorted key order, so two events of the same kind
// produce the same attribute order.
//
// A nil logger falls back to slog.Default rather than panicking on the first
// event — a forgotten logger should be a misconfiguration, not an outage.
func NewSlogSink(logger *slog.Logger) EventSink {
	if logger == nil {
		logger = slog.Default()
	}
	return slogSink{logger: logger}
}

type slogSink struct{ logger *slog.Logger }

func (s slogSink) Emit(ctx context.Context, e Event) {
	attrs := make([]slog.Attr, 0, 6+len(e.Metadata))
	attrs = append(attrs, slog.String("kind", string(e.Kind)))
	if e.UserID != "" {
		attrs = append(attrs, slog.String("user_id", e.UserID))
	}
	if e.SessionID != "" {
		attrs = append(attrs, slog.String("session_id", e.SessionID))
	}
	if e.RequestInfo.IP != "" {
		attrs = append(attrs, slog.String("ip", e.RequestInfo.IP))
	}
	if e.RequestInfo.UserAgent != "" {
		attrs = append(attrs, slog.String("user_agent", e.RequestInfo.UserAgent))
	}
	if !e.At.IsZero() {
		attrs = append(attrs, slog.Time("at", e.At))
	}
	for _, k := range slices.Sorted(maps.Keys(e.Metadata)) {
		attrs = append(attrs, slog.String(string(k), e.Metadata[k]))
	}
	s.logger.LogAttrs(ctx, slog.LevelInfo, "sulis security event", attrs...)
}
