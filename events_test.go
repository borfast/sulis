package sulis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- T509: security event sink ----------------------------------------------

// recordingSink is the test double for EventSink. It follows fakeLimiter's
// shape deliberately — a mutex, a slice of everything it was handed, and
// accessors tests read after the flow under test has returned — so the two
// observation points in this package look the same to a reader.
type recordingSink struct {
	mu     sync.Mutex
	events []Event
	// panicOn, when non-empty, makes Emit panic on that kind. It exists for
	// TestEventSinkPanicDoesNotFailTheFlow: a sink is application code, and
	// application code that panics must not be able to deny authentication.
	panicOn EventKind
}

func (r *recordingSink) Emit(_ context.Context, e Event) {
	r.mu.Lock()
	r.events = append(r.events, e)
	shouldPanic := r.panicOn != "" && e.Kind == r.panicOn
	r.mu.Unlock()
	if shouldPanic {
		panic("recordingSink: deliberate panic for " + string(e.Kind))
	}
}

func (r *recordingSink) all() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.events)
}

func (r *recordingSink) kinds() []EventKind {
	seen := map[EventKind]bool{}
	var out []EventKind
	for _, e := range r.all() {
		if !seen[e.Kind] {
			seen[e.Kind] = true
			out = append(out, e.Kind)
		}
	}
	return out
}

// first returns the earliest recorded event of the given kind.
func (r *recordingSink) first(kind EventKind) (Event, bool) {
	for _, e := range r.all() {
		if e.Kind == kind {
			return e, true
		}
	}
	return Event{}, false
}

// sweepRequestInfo is the RequestInfo every sweep flow that takes one is
// given, so tests can assert an event carried it through.
var sweepRequestInfo = RequestInfo{IP: "198.51.100.7", UserAgent: "sulis-sweep/1.0"}

// --- Per-decision-point taxonomy --------------------------------------------

// TestEachDecisionPointEmitsItsEventKind walks the taxonomy one decision at a
// time: each case drives exactly one flow to exactly one outcome and asserts
// the kind (and, where the kind alone would not distinguish the branch, the
// reason metadata) that outcome must produce.
//
// It is deliberately separate from the whole-package sweep below. The sweep
// proves every declared kind is reachable and that nothing leaks; this proves
// each kind is emitted by the flow that is supposed to emit it, so a
// copy-paste that fires the wrong kind from the wrong branch is caught rather
// than absorbed into an aggregate "all kinds seen" assertion.
func TestEachDecisionPointEmitsItsEventKind(t *testing.T) {
	for _, tc := range []struct {
		name       string
		want       EventKind
		wantReason string
		run        func(t *testing.T, sink *recordingSink)
	}{
		{
			name: "Register creates an account",
			want: EventAccountRegistered,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				mustRegister(t, s, "alice@example.com", "correct-battery-staple")
			},
		},
		{
			name: "a session is issued",
			want: EventSessionIssued,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				mustRegister(t, s, "alice@example.com", "correct-battery-staple")
			},
		},
		{
			name: "a correct password verifies",
			want: EventLoginSucceeded,
			run: func(t *testing.T, sink *recordingSink) {
				s, users, _, _ := newTestEnv(eventOpts(sink)...)
				u := mustRegister(t, s, "alice@example.com", "correct-battery-staple")
				verifyUserEmail(t, users, u.ID)
				if _, err := s.Login(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo); err != nil {
					t.Fatalf("Login: %v", err)
				}
			},
		},
		{
			name:       "a wrong password is refused",
			want:       EventLoginFailed,
			wantReason: ReasonWrongPassword,
			run: func(t *testing.T, sink *recordingSink) {
				s, users, _, _ := newTestEnv(eventOpts(sink)...)
				u := mustRegister(t, s, "alice@example.com", "correct-battery-staple")
				verifyUserEmail(t, users, u.ID)
				_, _ = s.Login(context.Background(), "alice@example.com", "wrong-battery-staple", sweepRequestInfo)
			},
		},
		{
			name:       "an unknown address is refused",
			want:       EventLoginFailed,
			wantReason: ReasonUserNotFound,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				_, _ = s.Login(context.Background(), "nobody@example.com", "correct-battery-staple", sweepRequestInfo)
			},
		},
		{
			name:       "an unverified address is refused after the password verifies",
			want:       EventLoginFailed,
			wantReason: ReasonEmailNotVerified,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				mustRegister(t, s, "alice@example.com", "correct-battery-staple")
				_, _ = s.Login(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo)
			},
		},
		{
			name:       "a disabled account is refused",
			want:       EventLoginFailed,
			wantReason: ReasonAccountDisabled,
			run: func(t *testing.T, sink *recordingSink) {
				s, users, _, _ := newTestEnv(eventOpts(sink)...)
				u := mustRegister(t, s, "alice@example.com", "correct-battery-staple")
				verifyUserEmail(t, users, u.ID)
				if err := s.DisableUser(context.Background(), u.ID, "abuse"); err != nil {
					t.Fatalf("DisableUser: %v", err)
				}
				_, _ = s.Login(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo)
			},
		},
		{
			name: "an operator disables an account",
			want: EventAccountDisabled,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				u := mustRegister(t, s, "alice@example.com", "correct-battery-staple")
				if err := s.DisableUser(context.Background(), u.ID, "abuse"); err != nil {
					t.Fatalf("DisableUser: %v", err)
				}
			},
		},
		{
			name: "an operator re-enables an account",
			want: EventAccountEnabled,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				u := mustRegister(t, s, "alice@example.com", "correct-battery-staple")
				if err := s.EnableUser(context.Background(), u.ID); err != nil {
					t.Fatalf("EnableUser: %v", err)
				}
			},
		},
		{
			name: "repeated failures lock the account",
			want: EventAccountLocked,
			run: func(t *testing.T, sink *recordingSink) {
				opts := append(eventOpts(sink), WithFailureLockout(2, time.Minute, time.Hour))
				s, users, _, _ := newTestEnv(opts...)
				u := mustRegister(t, s, "alice@example.com", "correct-battery-staple")
				verifyUserEmail(t, users, u.ID)
				for range 2 {
					_, _ = s.Login(context.Background(), "alice@example.com", "wrong-battery-staple", sweepRequestInfo)
				}
			},
		},
		{
			name: "a correct password clears a stale lockout",
			want: EventAccountLockoutCleared,
			run: func(t *testing.T, sink *recordingSink) {
				opts := append(eventOpts(sink), WithFailureLockout(2, time.Minute, time.Hour))
				s, users, _, _ := newTestEnv(opts...)
				u := mustRegister(t, s, "alice@example.com", "correct-battery-staple")
				verifyUserEmail(t, users, u.ID)
				lockUserUntil(t, users, u.ID, time.Now().Add(-time.Minute))
				if _, err := s.Login(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo); err != nil {
					t.Fatalf("Login: %v", err)
				}
			},
		},
		{
			name: "an enrolled second factor is demanded",
			want: EventSecondFactorDemanded,
			run: func(t *testing.T, sink *recordingSink) {
				s, users, _, _, factors := newTestEnvWithFactors(eventOpts(sink)...)
				u := mustRegister(t, s, "alice@example.com", "correct-battery-staple")
				verifyUserEmail(t, users, u.ID)
				factors.enroll(u.ID)
				if _, err := s.Login(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo); err != nil {
					t.Fatalf("Login: %v", err)
				}
			},
		},
		{
			name: "a second factor completes",
			want: EventSecondFactorCompleted,
			run: func(t *testing.T, sink *recordingSink) {
				s, users, _, _, factors := newTestEnvWithFactors(eventOpts(sink)...)
				u := mustRegister(t, s, "alice@example.com", "correct-battery-staple")
				verifyUserEmail(t, users, u.ID)
				factors.enroll(u.ID)
				res, err := s.Login(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo)
				if err != nil {
					t.Fatalf("Login: %v", err)
				}
				if _, err := s.CompleteTwoFactor(context.Background(), u.ID, res.PendingToken, sweepRequestInfo); err != nil {
					t.Fatalf("CompleteTwoFactor: %v", err)
				}
			},
		},
		{
			name:       "a bogus pending token is refused",
			want:       EventSecondFactorFailed,
			wantReason: ReasonTokenInvalid,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				u := mustRegister(t, s, "alice@example.com", "correct-battery-staple")
				_, _ = s.CompleteTwoFactor(context.Background(), u.ID, "not-a-real-token", sweepRequestInfo)
			},
		},
		{
			name: "a session past its absolute expiry is rejected",
			want: EventSessionExpired,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, sessions, _ := newTestEnv(eventOpts(sink)...)
				_, session, token, err := s.Register(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo)
				if err != nil {
					t.Fatalf("Register: %v", err)
				}
				sessions.mu.Lock()
				sessions.sessions[session.ID].ExpiresAt = time.Now().Add(-time.Second)
				sessions.mu.Unlock()
				_, _, _ = s.ValidateSession(context.Background(), token)
			},
		},
		{
			name: "a session past its idle deadline is rejected",
			want: EventSessionIdleExpired,
			run: func(t *testing.T, sink *recordingSink) {
				opts := append(eventOpts(sink), WithIdleTimeout(time.Hour))
				s, _, sessions, _ := newTestEnv(opts...)
				_, session, token, err := s.Register(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo)
				if err != nil {
					t.Fatalf("Register: %v", err)
				}
				past := time.Now().Add(-time.Second)
				sessions.mu.Lock()
				sessions.sessions[session.ID].IdleExpiresAt = &past
				sessions.mu.Unlock()
				_, _, _ = s.ValidateSession(context.Background(), token)
			},
		},
		{
			name: "a session is refreshed",
			want: EventSessionRefreshed,
			run: func(t *testing.T, sink *recordingSink) {
				s, users, _, _ := newTestEnv(eventOpts(sink)...)
				_, session, _, err := s.Register(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo)
				if err != nil {
					t.Fatalf("Register: %v", err)
				}
				// RefreshSession applies RequireVerifiedEmail like every
				// other minting path; verification is incidental here.
				verifyUserEmail(t, users, session.UserID)
				if _, _, err := s.RefreshSession(context.Background(), session); err != nil {
					t.Fatalf("RefreshSession: %v", err)
				}
			},
		},
		{
			name: "a single session is revoked",
			want: EventSessionRevoked,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				u, session, _, err := s.Register(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo)
				if err != nil {
					t.Fatalf("Register: %v", err)
				}
				if err := s.RevokeSession(context.Background(), u.ID, session.ID); err != nil {
					t.Fatalf("RevokeSession: %v", err)
				}
			},
		},
		{
			name: "a password is changed",
			want: EventPasswordChanged,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				u := mustRegister(t, s, "alice@example.com", "correct-battery-staple")
				if err := s.ChangePassword(context.Background(), u.ID, "correct-battery-staple", "new-correct-battery-staple", sweepRequestInfo); err != nil {
					t.Fatalf("ChangePassword: %v", err)
				}
			},
		},
		{
			name: "an initial password is set",
			want: EventPasswordSet,
			run: func(t *testing.T, sink *recordingSink) {
				s, users, _, _ := newTestEnv(eventOpts(sink)...)
				u := mustPasswordlessUser(t, s, users, "passwordless@example.com")
				if err := s.SetInitialPassword(context.Background(), u.ID, "correct-battery-staple"); err != nil {
					t.Fatalf("SetInitialPassword: %v", err)
				}
			},
		},
		{
			name: "a password reset is requested",
			want: EventPasswordResetRequested,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				mustRegister(t, s, "alice@example.com", "correct-battery-staple")
				if _, err := s.CreatePasswordResetToken(context.Background(), "alice@example.com", sweepRequestInfo); err != nil {
					t.Fatalf("CreatePasswordResetToken: %v", err)
				}
			},
		},
		{
			name: "a password is reset",
			want: EventPasswordReset,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				mustRegister(t, s, "alice@example.com", "correct-battery-staple")
				raw, err := s.CreatePasswordResetToken(context.Background(), "alice@example.com", sweepRequestInfo)
				if err != nil {
					t.Fatalf("CreatePasswordResetToken: %v", err)
				}
				if err := s.ResetPassword(context.Background(), raw, "new-correct-battery-staple"); err != nil {
					t.Fatalf("ResetPassword: %v", err)
				}
			},
		},
		{
			name: "a weak stored hash is upgraded on login",
			want: EventPasswordRehashed,
			run: func(t *testing.T, sink *recordingSink) {
				users, sessions, tokens := newMemUserStore(), newMemSessionStore(), newMemTokenStore()
				weak := mustNew(users, sessions, tokens, WithArgon2Params(weakerArgon2Params), WithEventSink(sink), WithoutRateLimiting())
				u, _, _, err := weak.Register(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo)
				if err != nil {
					t.Fatalf("Register: %v", err)
				}
				verifyUserEmail(t, users, u.ID)
				strong := mustNew(users, sessions, tokens, WithArgon2Params(testArgon2Params), WithEventSink(sink), WithoutRateLimiting())
				if _, err := strong.Login(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo); err != nil {
					t.Fatalf("Login: %v", err)
				}
			},
		},
		{
			name:       "a failed rehash write is reported, not swallowed silently",
			want:       EventPasswordRehashFailed,
			wantReason: ReasonStoreFailed,
			run: func(t *testing.T, sink *recordingSink) {
				mem := newMemUserStore()
				users := &failUpdateUserStore{memUserStore: mem}
				sessions, tokens := newMemSessionStore(), newMemTokenStore()
				weak := mustNew(users, sessions, tokens, WithArgon2Params(weakerArgon2Params), WithEventSink(sink), WithoutRateLimiting())
				u, _, _, err := weak.Register(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo)
				if err != nil {
					t.Fatalf("Register: %v", err)
				}
				verifyUserEmail(t, mem, u.ID)
				users.updateErr = fmt.Errorf("store unavailable")
				strong := mustNew(users, sessions, tokens, WithArgon2Params(testArgon2Params), WithEventSink(sink), WithoutRateLimiting())
				if _, err := strong.Login(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo); err != nil {
					t.Fatalf("Login: %v — a failed rehash must not fail the login", err)
				}
			},
		},
		{
			name: "a pre-NFKC stored hash matched only through the legacy fallback",
			want: EventPasswordLegacyFormMatched,
			run: func(t *testing.T, sink *recordingSink) {
				s, users, _, _ := newTestEnv(eventOpts(sink)...)
				u := mustLegacyHashUser(t, s, users, "legacy@example.com", nfkcCompatibilityForm)
				verifyUserEmail(t, users, u.ID)
				if _, err := s.Login(context.Background(), "legacy@example.com", nfkcCompatibilityForm, sweepRequestInfo); err != nil {
					t.Fatalf("Login with the pre-NFKC form: %v", err)
				}
			},
		},
		{
			name: "an email address is verified",
			want: EventEmailVerified,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				u := mustRegister(t, s, "alice@example.com", "correct-battery-staple")
				raw, err := s.CreateEmailVerificationToken(context.Background(), u.ID)
				if err != nil {
					t.Fatalf("CreateEmailVerificationToken: %v", err)
				}
				if _, err := s.VerifyEmail(context.Background(), raw); err != nil {
					t.Fatalf("VerifyEmail: %v", err)
				}
			},
		},
		{
			name: "an email change is staged",
			want: EventEmailChangeStaged,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				u := mustRegister(t, s, "alice@example.com", "correct-battery-staple")
				if _, err := s.ChangeEmail(context.Background(), u.ID, "alice-new@example.com"); err != nil {
					t.Fatalf("ChangeEmail: %v", err)
				}
			},
		},
		{
			name: "an email change is confirmed",
			want: EventEmailChangeConfirmed,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				u := mustRegister(t, s, "alice@example.com", "correct-battery-staple")
				raw, err := s.ChangeEmail(context.Background(), u.ID, "alice-new@example.com")
				if err != nil {
					t.Fatalf("ChangeEmail: %v", err)
				}
				if _, err := s.ConfirmEmailChange(context.Background(), raw); err != nil {
					t.Fatalf("ConfirmEmailChange: %v", err)
				}
			},
		},
		{
			name: "a magic link is created",
			want: EventMagicLinkCreated,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				if _, _, err := s.CreateMagicLinkToken(context.Background(), "alice@example.com", sweepRequestInfo); err != nil {
					t.Fatalf("CreateMagicLinkToken: %v", err)
				}
			},
		},
		{
			name: "a magic link is redeemed",
			want: EventMagicLinkRedeemed,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				raw, nonce, err := s.CreateMagicLinkToken(context.Background(), "alice@example.com", sweepRequestInfo)
				if err != nil {
					t.Fatalf("CreateMagicLinkToken: %v", err)
				}
				if _, err := s.RedeemMagicLink(context.Background(), raw, nonce, sweepRequestInfo); err != nil {
					t.Fatalf("RedeemMagicLink: %v", err)
				}
			},
		},
		{
			name:       "a magic link with the wrong binding nonce is rejected",
			want:       EventMagicLinkRejected,
			wantReason: ReasonBindingMismatch,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				raw, _, err := s.CreateMagicLinkToken(context.Background(), "alice@example.com", sweepRequestInfo)
				if err != nil {
					t.Fatalf("CreateMagicLinkToken: %v", err)
				}
				_, _ = s.RedeemMagicLink(context.Background(), raw, "not-the-nonce", sweepRequestInfo)
			},
		},
		{
			name:       "an unknown magic-link token is rejected",
			want:       EventMagicLinkRejected,
			wantReason: ReasonTokenInvalid,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				_, _ = s.RedeemMagicLink(context.Background(), "not-a-real-token", "", sweepRequestInfo)
			},
		},
		{
			name:       "the account dimension of the limiter denies",
			want:       EventRateLimitTripped,
			wantReason: "",
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithEventSink(sink), WithLimiter(&fakeLimiter{denied: true}))
				_, _ = s.Login(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo)
			},
		},
		{
			name: "a step-up re-authentication succeeds",
			want: EventReauthSucceeded,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				_, session, _, err := s.Register(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo)
				if err != nil {
					t.Fatalf("Register: %v", err)
				}
				if err := s.ReAuthenticate(context.Background(), session, "correct-battery-staple", sweepRequestInfo); err != nil {
					t.Fatalf("ReAuthenticate: %v", err)
				}
			},
		},
		{
			name:       "a step-up re-authentication with the wrong password fails",
			want:       EventReauthFailed,
			wantReason: ReasonWrongPassword,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				_, session, _, err := s.Register(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo)
				if err != nil {
					t.Fatalf("Register: %v", err)
				}
				_ = s.ReAuthenticate(context.Background(), session, "wrong-battery-staple", sweepRequestInfo)
			},
		},
		{
			name:       "the CSRF middleware rejects a request",
			want:       EventCSRFRejected,
			wantReason: ReasonCSRFTokenInvalid,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				h := s.RequireCSRFToken(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
				req := httptest.NewRequest(http.MethodPost, "https://app.example.com/x", nil)
				h.ServeHTTP(httptest.NewRecorder(), req)
			},
		},
		{
			name:       "the same-origin middleware rejects a cross-site request",
			want:       EventSameOriginRejected,
			wantReason: ReasonCrossSite,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				h := s.RequireSameOrigin([]string{"https://app.example.com"})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
				req := httptest.NewRequest(http.MethodPost, "https://app.example.com/x", nil)
				req.Header.Set("Sec-Fetch-Site", "cross-site")
				h.ServeHTTP(httptest.NewRecorder(), req)
			},
		},
		{
			name:       "the same-origin middleware rejects an unlisted Origin",
			want:       EventSameOriginRejected,
			wantReason: ReasonOriginNotAllowed,
			run: func(t *testing.T, sink *recordingSink) {
				s, _, _, _ := newTestEnv(eventOpts(sink)...)
				h := s.RequireSameOrigin([]string{"https://app.example.com"})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
				req := httptest.NewRequest(http.MethodPost, "https://app.example.com/x", nil)
				req.Header.Set("Origin", "https://evil.example.com")
				h.ServeHTTP(httptest.NewRecorder(), req)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &recordingSink{}
			tc.run(t, sink)

			got, ok := sink.first(tc.want)
			if !ok {
				t.Fatalf("no %s event emitted; got kinds %v", tc.want, sink.kinds())
			}
			if tc.wantReason != "" && got.Metadata[MetaReason] != tc.wantReason {
				t.Fatalf("%s reason = %q, want %q", tc.want, got.Metadata[MetaReason], tc.wantReason)
			}
			if got.At.IsZero() {
				t.Fatalf("%s carries a zero At timestamp", tc.want)
			}
		})
	}
}

// TestRateLimitEventNamesTheIPDimension asserts the IP half of the limiter's
// two dimensions is distinguishable in the event, not folded into one
// undifferentiated "rate limited" signal — telling "one host is spraying many
// accounts" apart from "one account is being guessed" is the whole point of
// the two keys existing (T106).
func TestRateLimitEventNamesTheIPDimension(t *testing.T) {
	sink := &recordingSink{}
	s, _, _, _ := newTestEnv(
		WithArgon2Params(testArgon2Params),
		WithEventSink(sink),
		WithLimiter(&ipOnlyDenyLimiter{}),
	)

	_, _ = s.Login(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo)

	e, ok := sink.first(EventRateLimitTripped)
	if !ok {
		t.Fatalf("no %s event; got kinds %v", EventRateLimitTripped, sink.kinds())
	}
	if got := e.Metadata[MetaDimension]; got != DimensionIP {
		t.Fatalf("dimension = %q, want %q", got, DimensionIP)
	}
	if got := e.Metadata[MetaScope]; got != "password" {
		t.Fatalf("scope = %q, want %q", got, "password")
	}
	if e.RequestInfo.IP != sweepRequestInfo.IP {
		t.Fatalf("RequestInfo.IP = %q, want %q", e.RequestInfo.IP, sweepRequestInfo.IP)
	}
}

// TestSessionIssuedEventCarriesTheAuthMethod asserts that the one event every
// authenticated flow funnels through records *which* credential authorized
// the session, so a sink can tell a password sign-in from a magic-link one
// without correlating against a second event.
func TestSessionIssuedEventCarriesTheAuthMethod(t *testing.T) {
	sink := &recordingSink{}
	s, _, _, _ := newTestEnv(eventOpts(sink)...)
	ctx := context.Background()

	raw, nonce, err := s.CreateMagicLinkToken(ctx, "alice@example.com", sweepRequestInfo)
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	if _, err := s.RedeemMagicLink(ctx, raw, nonce, sweepRequestInfo); err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}

	e, ok := sink.first(EventSessionIssued)
	if !ok {
		t.Fatalf("no %s event; got kinds %v", EventSessionIssued, sink.kinds())
	}
	if got := e.Metadata[MetaMethod]; got != string(AuthMethodMagicLink) {
		t.Fatalf("method = %q, want %q", got, AuthMethodMagicLink)
	}
	if e.SessionID == "" {
		t.Fatal("session.issued carries no SessionID")
	}
	if e.UserID == "" {
		t.Fatal("session.issued carries no UserID")
	}
}

// TestBestEffortHelperEventsCarryRequestInfo pins the fix round's minor
// finding: the four events emitted from best-effort bookkeeping helpers
// (rehashPassword's two, recordFailedLogin's, clearFailedLogins's) are
// attributable to the request that triggered them.
//
// These are exactly the events an operator reaches for when something looks
// wrong — a store quietly refusing every hash upgrade, an account being
// walked into lockout — and every one of their callers has a RequestInfo in
// hand. That distinguishes them from ValidateSession's and RefreshSession's
// events, which stay zero because their methods take none and the session's
// own IP describes a different, older request.
func TestBestEffortHelperEventsCarryRequestInfo(t *testing.T) {
	t.Run("password.rehashed", func(t *testing.T) {
		sink := &recordingSink{}
		users, sessions, tokens := newMemUserStore(), newMemSessionStore(), newMemTokenStore()
		weak := mustNew(users, sessions, tokens, WithArgon2Params(weakerArgon2Params), WithEventSink(sink), WithoutRateLimiting())
		u, _, _, err := weak.Register(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo)
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		verifyUserEmail(t, users, u.ID)
		strong := mustNew(users, sessions, tokens, WithArgon2Params(testArgon2Params), WithEventSink(sink), WithoutRateLimiting())
		if _, err := strong.Login(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo); err != nil {
			t.Fatalf("Login: %v", err)
		}
		assertCarriesSweepRequestInfo(t, sink, EventPasswordRehashed)
	})

	t.Run("password.rehash_failed", func(t *testing.T) {
		sink := &recordingSink{}
		mem := newMemUserStore()
		users := &failUpdateUserStore{memUserStore: mem}
		sessions, tokens := newMemSessionStore(), newMemTokenStore()
		weak := mustNew(users, sessions, tokens, WithArgon2Params(weakerArgon2Params), WithEventSink(sink), WithoutRateLimiting())
		u, _, _, err := weak.Register(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo)
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		verifyUserEmail(t, mem, u.ID)
		users.updateErr = fmt.Errorf("store unavailable")
		strong := mustNew(users, sessions, tokens, WithArgon2Params(testArgon2Params), WithEventSink(sink), WithoutRateLimiting())
		if _, err := strong.Login(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo); err != nil {
			t.Fatalf("Login: %v", err)
		}
		assertCarriesSweepRequestInfo(t, sink, EventPasswordRehashFailed)
	})

	t.Run("account.locked", func(t *testing.T) {
		sink := &recordingSink{}
		opts := append(eventOpts(sink), WithFailureLockout(2, time.Minute, time.Hour))
		s, users, _, _ := newTestEnv(opts...)
		u := mustRegister(t, s, "alice@example.com", "correct-battery-staple")
		verifyUserEmail(t, users, u.ID)
		for range 2 {
			_, _ = s.Login(context.Background(), "alice@example.com", "wrong-battery-staple", sweepRequestInfo)
		}
		assertCarriesSweepRequestInfo(t, sink, EventAccountLocked)
	})

	t.Run("account.lockout_cleared", func(t *testing.T) {
		sink := &recordingSink{}
		opts := append(eventOpts(sink), WithFailureLockout(2, time.Minute, time.Hour))
		s, users, _, _ := newTestEnv(opts...)
		u := mustRegister(t, s, "alice@example.com", "correct-battery-staple")
		verifyUserEmail(t, users, u.ID)
		lockUserUntil(t, users, u.ID, time.Now().Add(-time.Minute))
		if _, err := s.Login(context.Background(), "alice@example.com", "correct-battery-staple", sweepRequestInfo); err != nil {
			t.Fatalf("Login: %v", err)
		}
		assertCarriesSweepRequestInfo(t, sink, EventAccountLockoutCleared)
	})
}

// TestUnrecognizedGateVerdictOmitsTheReasonKey pins the defensive default
// the three refusal helpers share: gateReason returns "" for a verdict it
// does not recognize, and the helpers then omit the reason key rather than
// filling it with a guess. A label that might be wrong is worse than an
// absent one, since a sink cannot tell the two apart after the fact.
//
// The branch is not reachable through any current flow — gateReason covers
// every sentinel accountStatus and requireVerifiedEmail can return — so the
// helpers are exercised directly, the same way lockoutBackoff is unit-tested
// past what a flow can drive it to.
func TestUnrecognizedGateVerdictOmitsTheReasonKey(t *testing.T) {
	if got := gateReason(errors.New("something else entirely")); got != "" {
		t.Fatalf("gateReason of an unrecognized error = %q, want \"\"", got)
	}

	sink := &recordingSink{}
	s, _, _, _ := newTestEnv(eventOpts(sink)...)
	ctx := context.Background()
	session := &Session{ID: "session-1", UserID: "user-1"}

	s.emitLoginFailedVia(ctx, "user-1", sweepRequestInfo, AuthMethodPassword, "")
	s.emitSecondFactorFailed(ctx, "user-1", sweepRequestInfo, "")
	s.emitReauthFailed(ctx, session, sweepRequestInfo, "")

	for _, kind := range []EventKind{EventLoginFailed, EventSecondFactorFailed, EventReauthFailed} {
		e, ok := sink.first(kind)
		if !ok {
			t.Fatalf("no %s event; got kinds %v", kind, sink.kinds())
		}
		if _, present := e.Metadata[MetaReason]; present {
			t.Fatalf("%s carries a reason key for an unrecognized verdict: %v", kind, e.Metadata)
		}
	}

	// The method label still survives on login.failed — only the reason is
	// dropped, not the whole metadata map.
	e, _ := sink.first(EventLoginFailed)
	if e.Metadata[MetaMethod] != string(AuthMethodPassword) {
		t.Fatalf("login.failed method = %q, want %q", e.Metadata[MetaMethod], AuthMethodPassword)
	}
}

func assertCarriesSweepRequestInfo(t *testing.T, sink *recordingSink, kind EventKind) {
	t.Helper()
	e, ok := sink.first(kind)
	if !ok {
		t.Fatalf("no %s event; got kinds %v", kind, sink.kinds())
	}
	if e.RequestInfo != sweepRequestInfo {
		t.Fatalf("%s RequestInfo = %+v, want %+v", kind, e.RequestInfo, sweepRequestInfo)
	}
}

// --- The no-secrets property ------------------------------------------------

// TestNoEventCarriesSecretMaterial is the security core of T509. It drives
// every flow in this package that emits an event, then scans every field of
// every emitted event for every secret those flows were fed.
//
// "Secret" is drawn deliberately wide: not only the values the brief names
// (passwords, reset/magic-link/two-factor/verification tokens, session
// tokens, the magic-link binding nonce) but also the stored password hashes,
// the stored session token hashes, the submitted email addresses, and the
// operator-supplied disable reason. The last three are not secrets in the
// credential sense; they are there because the design rule this test pins is
// stronger than "no credentials": *no caller-supplied string is ever copied
// into an event*, RequestInfo excepted. Users type passwords into the email
// field, and operators type who-knows-what into a disable reason. An event
// taxonomy that copies caller input is one bad day away from being a
// credential log.
func TestNoEventCarriesSecretMaterial(t *testing.T) {
	sink, secrets := eventFlowSweep(t)

	events := sink.all()
	if len(events) == 0 {
		t.Fatal("the sweep emitted no events at all; the scan below would be vacuous")
	}

	for i, e := range events {
		for name, secret := range secrets {
			if found := scanEventFor(t, e, secret); found {
				t.Errorf("event %d (%s) contains the value of %s", i, e.Kind, name)
			}
		}
	}
}

// TestEventSecretScanCatchesAPlantedSecret is the permanent, checked-in half
// of the mutation test for the property above: it plants a secret in each
// field an Event actually has and asserts the scanner notices. Without it,
// TestNoEventCarriesSecretMaterial could pass because the scanner is broken
// rather than because the events are clean, and nothing would say which.
func TestEventSecretScanCatchesAPlantedSecret(t *testing.T) {
	const secret = "s3cr3t-raw-token-value"

	for _, tc := range []struct {
		name  string
		event Event
	}{
		{"UserID", Event{Kind: EventLoginFailed, UserID: secret}},
		{"SessionID", Event{Kind: EventLoginFailed, SessionID: secret}},
		{"RequestInfo.IP", Event{Kind: EventLoginFailed, RequestInfo: RequestInfo{IP: secret}}},
		{"RequestInfo.UserAgent", Event{Kind: EventLoginFailed, RequestInfo: RequestInfo{UserAgent: secret}}},
		{"Metadata value", Event{Kind: EventLoginFailed, Metadata: map[MetadataKey]string{MetaReason: secret}}},
		{"Metadata key", Event{Kind: EventLoginFailed, Metadata: map[MetadataKey]string{MetadataKey(secret): "x"}}},
		{"Kind", Event{Kind: EventKind(secret)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !scanEventFor(t, tc.event, secret) {
				t.Fatalf("the scanner missed a secret planted in %s; TestNoEventCarriesSecretMaterial cannot be trusted", tc.name)
			}
		})
	}

	if scanEventFor(t, Event{Kind: EventLoginFailed, UserID: "an-ordinary-id"}, secret) {
		t.Fatal("the scanner reports a secret in an event that has none")
	}
}

// scanEventFor reports whether e carries secret anywhere. It looks at two
// independent renderings — encoding/json, which walks the exported fields a
// sink would realistically serialize, and %#v, which prints the Go value
// including anything JSON would elide — so a field added later is covered by
// at least one of them without this test being updated.
func scanEventFor(t *testing.T, e Event, secret string) bool {
	t.Helper()
	if secret == "" {
		t.Fatal("scanEventFor: empty secret; the scan would match everything")
	}

	encoded, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshalling event: %v", err)
	}
	haystack := string(encoded) + "\n" + fmt.Sprintf("%#v", e)

	return strings.Contains(haystack, secret) ||
		strings.Contains(strings.ToLower(haystack), strings.ToLower(secret))
}

// --- Taxonomy completeness --------------------------------------------------

// TestEveryDeclaredEventKindIsEmitted asserts that every EventKind constant
// declared in events.go is actually produced by some flow in the sweep. A
// kind nobody emits is documentation pretending to be observability, and a
// kind added later without a flow to emit it fails here rather than shipping
// as a promise the library does not keep.
//
// The list of kinds is read out of events.go's source rather than kept in a
// slice here, following the same implementation-inspection pattern
// TestVerifyCSRFTokenUsesConstantTimeCompare (csrf_test.go) established: a
// hand-maintained list in the test would silently stop covering a constant
// somebody forgot to add to it, which is the exact failure this test exists
// to prevent.
func TestEveryDeclaredEventKindIsEmitted(t *testing.T) {
	declared := declaredEventKinds(t)
	if len(declared) == 0 {
		t.Fatal("no EventKind constants found in events.go; the scan is broken")
	}

	sink, _ := eventFlowSweep(t)
	emitted := map[EventKind]bool{}
	for _, k := range sink.kinds() {
		emitted[k] = true
	}

	var missing []string
	for _, k := range declared {
		if !emitted[k] {
			missing = append(missing, string(k))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("declared but never emitted by any flow: %s", strings.Join(missing, ", "))
	}
}

// declaredEventKinds reads events.go and returns every EventKind constant
// value declared in it. Each constant repeats the `EventKind` type
// deliberately (rather than relying on a Go const block carrying the type
// down the list) so this scan can find them all.
func declaredEventKinds(t *testing.T) []EventKind {
	t.Helper()
	src, err := os.ReadFile("events.go")
	if err != nil {
		t.Fatalf("reading events.go: %v", err)
	}
	re := regexp.MustCompile(`(?m)^\s*Event\w+\s+EventKind\s*=\s*"([^"]+)"`)
	var out []EventKind
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		out = append(out, EventKind(m[1]))
	}
	return out
}

// --- The nil sink -----------------------------------------------------------

// TestNilEventSinkIsTheDefault pins that events are opt-in: a Sulis built
// with no options emits nowhere.
func TestNilEventSinkIsTheDefault(t *testing.T) {
	if got := defaultConfig().EventSink; got != nil {
		t.Fatalf("defaultConfig().EventSink = %v, want nil", got)
	}
}

// TestNilEventSinkIsANoOp asserts that with no sink configured, every flow
// behaves exactly as it did before this taxonomy existed. The emission path
// must be a nil check and nothing else.
func TestNilEventSinkIsANoOp(t *testing.T) {
	sink, _ := eventFlowSweep(t)
	withSink := len(sink.all())
	if withSink == 0 {
		t.Fatal("the sweep with a sink emitted nothing; the comparison below is vacuous")
	}

	// The same sweep with no sink configured must complete without error.
	// eventFlowSweep t.Fatal's on any unexpected failure, so reaching the
	// end of it is the assertion.
	nilSink, _ := eventFlowSweepWithSink(t, nil)
	if nilSink != nil {
		t.Fatal("eventFlowSweepWithSink(nil) returned a sink")
	}
}

// TestNilSinkPathAllocatesNothing is the empirical half of the guarantee the
// package doc, emit's GoDoc, and the README all make: with no sink
// configured, an emission costs one nil check and nothing else.
//
// It exists because the obvious way to write emit — a Metadata map built at
// the call site and passed in — quietly breaks that claim. Arguments are
// evaluated before the call, so the map would be allocated on every
// decision whether or not anybody was listening. emit takes variadic
// key/value pairs and builds the map after the nil check instead; this test
// is what stops that from being undone by a well-meaning refactor back to a
// map argument.
func TestNilSinkPathAllocatesNothing(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	if s.cfg.EventSink != nil {
		t.Fatal("this test needs a Sulis with no sink configured")
	}
	ctx := context.Background()

	allocs := testing.AllocsPerRun(100, func() {
		s.emit(ctx, Event{Kind: EventLoginFailed, UserID: "user-123"},
			string(MetaMethod), string(AuthMethodPassword),
			string(MetaReason), ReasonWrongPassword)
	})
	if allocs != 0 {
		t.Fatalf("emitting to a nil sink allocated %v objects per call, want 0 — metadata is being built before the nil-sink check", allocs)
	}
}

// TestNilSinkAllocationTestIsNotVacuous is the control for the above: the
// identical call, with a sink configured, must actually deliver the
// metadata. Without this, TestNilSinkPathAllocatesNothing would keep passing
// if emit stopped building the map at all.
func TestNilSinkAllocationTestIsNotVacuous(t *testing.T) {
	sink := &recordingSink{}
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithEventSink(sink))

	s.emit(context.Background(), Event{Kind: EventLoginFailed, UserID: "user-123"},
		string(MetaMethod), string(AuthMethodPassword),
		string(MetaReason), ReasonWrongPassword)

	e, ok := sink.first(EventLoginFailed)
	if !ok {
		t.Fatal("no event reached the configured sink")
	}
	if e.Metadata[MetaMethod] != string(AuthMethodPassword) || e.Metadata[MetaReason] != ReasonWrongPassword {
		t.Fatalf("metadata = %v, want both pairs present", e.Metadata)
	}
}

// TestOddMetaPairIsDroppedNotPanicked pins emit's handling of a caller
// mistake: an unpaired trailing label is a programming error in this
// package, and dropping it is the right response — panicking a login over
// an observability detail is not.
func TestOddMetaPairIsDroppedNotPanicked(t *testing.T) {
	sink := &recordingSink{}
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithEventSink(sink))

	s.emit(context.Background(), Event{Kind: EventLoginFailed},
		string(MetaReason), ReasonWrongPassword, string(MetaMethod))

	e, _ := sink.first(EventLoginFailed)
	if len(e.Metadata) != 1 || e.Metadata[MetaReason] != ReasonWrongPassword {
		t.Fatalf("metadata = %v, want only the complete pair", e.Metadata)
	}
}

// TestEventSinkPanicDoesNotFailTheFlow asserts an emission cannot change a
// flow's outcome even when the sink is outright broken. A sink is
// application code; application code that panics must not be able to deny
// authentication to everybody.
func TestEventSinkPanicDoesNotFailTheFlow(t *testing.T) {
	sink := &recordingSink{panicOn: EventLoginSucceeded}
	s, users, _, _ := newTestEnv(eventOpts(sink)...)
	ctx := context.Background()

	u := mustRegister(t, s, "alice@example.com", "correct-battery-staple")
	verifyUserEmail(t, users, u.ID)

	res, err := s.Login(ctx, "alice@example.com", "correct-battery-staple", sweepRequestInfo)
	if err != nil {
		t.Fatalf("Login: %v — a panicking sink must not fail the flow", err)
	}
	if res.Session == nil {
		t.Fatal("Login returned no session even though the credential was correct")
	}
}

// TestEmitStampsAtWhenAbsent asserts every event reaches the sink with a
// timestamp, so a sink never has to invent one and two sinks never disagree
// about when something happened.
func TestEmitStampsAtWhenAbsent(t *testing.T) {
	sink := &recordingSink{}
	s, _, _, _ := newTestEnv(eventOpts(sink)...)

	before := time.Now()
	mustRegister(t, s, "alice@example.com", "correct-battery-staple")
	after := time.Now()

	for _, e := range sink.all() {
		if e.At.Before(before) || e.At.After(after) {
			t.Fatalf("%s At = %v, outside [%v, %v]", e.Kind, e.At, before, after)
		}
	}
}

// --- The slog adapter -------------------------------------------------------

// TestSlogSinkWritesStructuredAttributes asserts the one-line wiring adapter
// actually produces structured attributes rather than a formatted string a
// log pipeline would have to re-parse.
func TestSlogSinkWritesStructuredAttributes(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	sink := NewSlogSink(logger)
	sink.Emit(context.Background(), Event{
		Kind:        EventLoginFailed,
		UserID:      "user-123",
		SessionID:   "session-456",
		RequestInfo: RequestInfo{IP: "198.51.100.7", UserAgent: "curl/8"},
		At:          time.Unix(1700000000, 0).UTC(),
		Metadata:    map[MetadataKey]string{MetaReason: ReasonWrongPassword, MetaMethod: string(AuthMethodPassword)},
	})

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("slog output is not JSON: %v (%s)", err, buf.String())
	}

	for key, want := range map[string]string{
		"kind":       string(EventLoginFailed),
		"user_id":    "user-123",
		"session_id": "session-456",
		"ip":         "198.51.100.7",
		"user_agent": "curl/8",
		"reason":     ReasonWrongPassword,
		"method":     string(AuthMethodPassword),
	} {
		if got[key] != want {
			t.Errorf("attr %q = %v, want %q", key, got[key], want)
		}
	}
}

// TestNewSlogSinkTolueratesANilLogger asserts the adapter falls back to
// slog.Default rather than panicking on the first event, which would make a
// forgotten logger an outage rather than a misconfiguration.
func TestNewSlogSinkToleratesANilLogger(t *testing.T) {
	// Point slog.Default at a discard handler for the duration, so the one
	// event this test emits does not land in the test output.
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(restore) })

	sink := NewSlogSink(nil)
	if sink == nil {
		t.Fatal("NewSlogSink(nil) returned nil")
	}
	sink.Emit(context.Background(), Event{Kind: EventLoginFailed, At: time.Now()})
}

// --- Sweep machinery --------------------------------------------------------

// eventOpts is the standard option set for an event test: fast Argon2, the
// sink under observation, and no rate limiting (the sweep makes far more
// attempts against one account than the default budget allows, and the
// limiter has its own dedicated cases above).
func eventOpts(sink EventSink) []Option {
	return []Option{WithArgon2Params(testArgon2Params), WithEventSink(sink), WithoutRateLimiting()}
}

// mustRegister registers a user and fails the test if it cannot.
func mustRegister(t *testing.T, s *Sulis, email, password string) *User {
	t.Helper()
	u, _, _, err := s.Register(context.Background(), email, password, sweepRequestInfo)
	if err != nil {
		t.Fatalf("Register(%s): %v", email, err)
	}
	return u
}

// mustPasswordlessUser creates an account with no password, the way a magic
// link would.
func mustPasswordlessUser(t *testing.T, s *Sulis, users *memUserStore, email string) *User {
	t.Helper()
	ctx := context.Background()
	raw, nonce, err := s.CreateMagicLinkToken(ctx, email, sweepRequestInfo)
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	if _, err := s.RedeemMagicLink(ctx, raw, nonce, sweepRequestInfo); err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}
	u, err := users.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	return u
}

// mustLegacyHashUser creates a user whose stored hash was derived from the
// raw bytes of password rather than its NFKC form — a hash written by a
// pre-T505 sulis. Logging in with the same raw form matches only through
// verifyPassword's compatibility fallback, which is the decision
// EventPasswordLegacyFormMatched reports.
func mustLegacyHashUser(t *testing.T, s *Sulis, users *memUserStore, email, password string) *User {
	t.Helper()
	ctx := context.Background()
	u := mustRegister(t, s, email, "placeholder-battery-staple")
	stored, err := users.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	stored.PasswordHash = legacyHash(t, password, testArgon2Params)
	if err := users.UpdateUser(ctx, stored); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	return stored
}

// ipOnlyDenyLimiter denies only the IP dimension of the limiter's two keys,
// so a test can reach allowIP's denial without allow's account-dimension
// denial short-circuiting the flow first.
type ipOnlyDenyLimiter struct{}

func (ipOnlyDenyLimiter) Allow(_ context.Context, key string) error {
	if strings.Contains(key, ":ip:") {
		return ErrRateLimited
	}
	return nil
}

// eventFlowSweep drives every flow in this package that emits an event
// against one recording sink, and returns the sink alongside every secret
// value the flows were fed (keyed by a human name, for the failure message).
func eventFlowSweep(t *testing.T) (*recordingSink, map[string]string) {
	t.Helper()
	sink := &recordingSink{}
	_, secrets := eventFlowSweepWithSink(t, sink)
	return sink, secrets
}

// eventFlowSweepWithSink is eventFlowSweep parameterized by the sink, so the
// identical sequence of flows can be run with no sink configured at all —
// which is how "a nil sink is a no-op" is asserted against the whole surface
// rather than one flow.
//
//nolint:gocyclo // one flow per decision point; splitting it hides the list.
func eventFlowSweepWithSink(t *testing.T, sink *recordingSink) (*recordingSink, map[string]string) {
	t.Helper()
	ctx := context.Background()

	secrets := map[string]string{}
	secret := func(name, value string) string {
		if value != "" {
			secrets[name] = value
		}
		return value
	}

	var sinkOpt EventSink
	if sink != nil {
		sinkOpt = sink
	}
	base := func(extra ...Option) []Option {
		opts := []Option{WithArgon2Params(testArgon2Params), WithoutRateLimiting()}
		if sinkOpt != nil {
			opts = append(opts, WithEventSink(sinkOpt))
		}
		return append(opts, extra...)
	}

	const (
		aliceEmail = "alice@example.com"
		alicePass  = "correct-battery-staple"
		aliceNew   = "new-correct-battery-staple"
		aliceNewer = "newer-correct-battery-staple"
	)
	secret("alice's password", alicePass)
	secret("alice's changed password", aliceNew)
	secret("alice's reset password", aliceNewer)
	secret("alice's email", aliceEmail)

	// --- password, session, account status -------------------------------
	s, users, sessions, _, factors := newTestEnvWithFactors(base()...)

	alice, session, regToken, err := s.Register(ctx, aliceEmail, alicePass, sweepRequestInfo)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	secret("alice's registration session token", regToken)

	// Unverified: the password verifies, then the gate refuses.
	if _, err := s.Login(ctx, aliceEmail, alicePass, sweepRequestInfo); err == nil {
		t.Fatal("Login for an unverified account unexpectedly succeeded")
	}

	verifyTok, err := s.CreateEmailVerificationToken(ctx, alice.ID)
	if err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}
	secret("alice's email-verification token", verifyTok)
	if _, err := s.VerifyEmail(ctx, verifyTok); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}

	res, err := s.Login(ctx, aliceEmail, alicePass, sweepRequestInfo)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	secret("alice's login session token", res.SessionToken)
	loginSession := res.Session

	if _, err := s.Login(ctx, aliceEmail, "wrong-battery-staple", sweepRequestInfo); err == nil {
		t.Fatal("Login with a wrong password unexpectedly succeeded")
	}
	if _, err := s.Login(ctx, "nobody@example.com", alicePass, sweepRequestInfo); err == nil {
		t.Fatal("Login for an unknown address unexpectedly succeeded")
	}

	// Session lifecycle.
	if _, _, err := s.ValidateSession(ctx, res.SessionToken); err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	refreshed, refreshTok, err := s.RefreshSession(ctx, loginSession)
	if err != nil {
		t.Fatalf("RefreshSession: %v", err)
	}
	secret("alice's refreshed session token", refreshTok)
	if err := s.RevokeSession(ctx, alice.ID, refreshed.ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if err := s.RevokeAllSessions(ctx, alice.ID); err != nil {
		t.Fatalf("RevokeAllSessions: %v", err)
	}

	// Absolute expiry.
	expiringRes, err := s.Login(ctx, aliceEmail, alicePass, sweepRequestInfo)
	if err != nil {
		t.Fatalf("Login (expiry fixture): %v", err)
	}
	secret("alice's expiring session token", expiringRes.SessionToken)
	sessions.mu.Lock()
	sessions.sessions[expiringRes.Session.ID].ExpiresAt = time.Now().Add(-time.Second)
	sessions.mu.Unlock()
	if _, _, err := s.ValidateSession(ctx, expiringRes.SessionToken); err == nil {
		t.Fatal("ValidateSession accepted an expired session")
	}

	// Idle expiry, on its own instance since it needs WithIdleTimeout.
	idleOpts := []Option{WithArgon2Params(testArgon2Params), WithoutRateLimiting(), WithIdleTimeout(time.Hour)}
	if sinkOpt != nil {
		idleOpts = append(idleOpts, WithEventSink(sinkOpt))
	}
	idle, _, idleSessions, _ := newTestEnv(idleOpts...)
	const idleEmail = "idle@example.com"
	const idlePass = "idle-battery-staple"
	secret("the idle address", idleEmail)
	secret("the idle password", idlePass)
	_, idleSession, idleToken, err := idle.Register(ctx, idleEmail, idlePass, sweepRequestInfo)
	if err != nil {
		t.Fatalf("Register (idle): %v", err)
	}
	secret("the idle session token", idleToken)
	pastIdle := time.Now().Add(-time.Second)
	idleSessions.mu.Lock()
	idleSessions.sessions[idleSession.ID].IdleExpiresAt = &pastIdle
	idleSessions.mu.Unlock()
	if _, _, err := idle.ValidateSession(ctx, idleToken); err == nil {
		t.Fatal("ValidateSession accepted a session past its idle deadline")
	}

	// Step-up.
	stepRes, err := s.Login(ctx, aliceEmail, alicePass, sweepRequestInfo)
	if err != nil {
		t.Fatalf("Login (step-up fixture): %v", err)
	}
	secret("alice's step-up session token", stepRes.SessionToken)
	if err := s.ReAuthenticate(ctx, stepRes.Session, alicePass, sweepRequestInfo); err != nil {
		t.Fatalf("ReAuthenticate: %v", err)
	}
	if err := s.ReAuthenticate(ctx, stepRes.Session, "wrong-battery-staple", sweepRequestInfo); err == nil {
		t.Fatal("ReAuthenticate with a wrong password unexpectedly succeeded")
	}

	// Password change / reset.
	if err := s.ChangePassword(ctx, alice.ID, alicePass, aliceNew, sweepRequestInfo); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	resetTok, err := s.CreatePasswordResetToken(ctx, aliceEmail, sweepRequestInfo)
	if err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}
	secret("alice's reset token", resetTok)
	if err := s.ResetPassword(ctx, resetTok, aliceNewer); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	// Email change.
	const aliceNewEmail = "alice-new@example.com"
	secret("alice's staged new email", aliceNewEmail)
	changeTok, err := s.ChangeEmail(ctx, alice.ID, aliceNewEmail)
	if err != nil {
		t.Fatalf("ChangeEmail: %v", err)
	}
	secret("alice's email-change token", changeTok)
	if _, err := s.ConfirmEmailChange(ctx, changeTok); err != nil {
		t.Fatalf("ConfirmEmailChange: %v", err)
	}

	// Second factor.
	factors.enroll(alice.ID)
	twoFactorRes, err := s.Login(ctx, aliceNewEmail, aliceNewer, sweepRequestInfo)
	if err != nil {
		t.Fatalf("Login (2FA): %v", err)
	}
	secret("alice's pending two-factor token", twoFactorRes.PendingToken)
	if !twoFactorRes.NeedsSecondFactor {
		t.Fatal("an enrolled second factor was not demanded")
	}
	completed, err := s.CompleteTwoFactor(ctx, alice.ID, twoFactorRes.PendingToken, sweepRequestInfo)
	if err != nil {
		t.Fatalf("CompleteTwoFactor: %v", err)
	}
	secret("alice's two-factor session token", completed.SessionToken)
	if _, err := s.CompleteTwoFactor(ctx, alice.ID, "not-a-real-token", sweepRequestInfo); err == nil {
		t.Fatal("CompleteTwoFactor accepted a bogus token")
	}
	standaloneTok, err := s.CreateTwoFactorToken(ctx, alice.ID)
	if err != nil {
		t.Fatalf("CreateTwoFactorToken: %v", err)
	}
	secret("alice's standalone two-factor token", standaloneTok)

	// Unchecked issuance (the passkey-shaped caller). It never consults the
	// SecondFactorChecker — that is what "unchecked" names — so the factor
	// enrolled just above does not have to be withdrawn first.
	if _, uncheckedTok, err := s.IssueSessionUnchecked(ctx, alice.ID, AuthMethodPasskey); err != nil {
		t.Fatalf("IssueSessionUnchecked: %v", err)
	} else {
		secret("alice's unchecked session token", uncheckedTok)
	}

	// Disable / enable.
	const disableReason = "operator-supplied disable reason"
	secret("the disable reason", disableReason)
	if err := s.DisableUser(ctx, alice.ID, disableReason); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	if _, err := s.Login(ctx, aliceNewEmail, aliceNewer, sweepRequestInfo); err == nil {
		t.Fatal("Login for a disabled account unexpectedly succeeded")
	}
	if err := s.EnableUser(ctx, alice.ID); err != nil {
		t.Fatalf("EnableUser: %v", err)
	}

	// Stored material that must never appear in an event either.
	storedAlice, err := users.GetUserByID(ctx, alice.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	secret("alice's stored password hash", storedAlice.PasswordHash)
	secret("alice's registration session token hash", session.TokenHash)

	// --- magic link -------------------------------------------------------
	magic, magicUsers, _, _ := newTestEnv(base()...)
	const magicEmail = "magic@example.com"
	secret("the magic-link address", magicEmail)

	magicTok, magicNonce, err := magic.CreateMagicLinkToken(ctx, magicEmail, sweepRequestInfo)
	if err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}
	secret("the magic-link token", magicTok)
	secret("the magic-link binding nonce", magicNonce)
	if _, err := magic.RedeemMagicLink(ctx, magicTok, magicNonce, sweepRequestInfo); err != nil {
		t.Fatalf("RedeemMagicLink: %v", err)
	}

	badTok, badNonce, err := magic.CreateMagicLinkToken(ctx, magicEmail, sweepRequestInfo)
	if err != nil {
		t.Fatalf("CreateMagicLinkToken (rejection fixture): %v", err)
	}
	secret("the rejected magic-link token", badTok)
	secret("the unused binding nonce", badNonce)
	if _, err := magic.RedeemMagicLink(ctx, badTok, "not-the-nonce", sweepRequestInfo); err == nil {
		t.Fatal("RedeemMagicLink accepted a wrong binding nonce")
	}

	// An initial password on the passwordless account the magic link made.
	magicUser, err := magicUsers.GetUserByEmail(ctx, magicEmail)
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	const magicInitialPass = "initial-battery-staple"
	secret("the initial password", magicInitialPass)
	if err := magic.SetInitialPassword(ctx, magicUser.ID, magicInitialPass); err != nil {
		t.Fatalf("SetInitialPassword: %v", err)
	}

	// --- rehash, legacy form ---------------------------------------------
	rehashUsers, rehashSessions, rehashTokens := newMemUserStore(), newMemSessionStore(), newMemTokenStore()
	weakOpts := base(WithArgon2Params(weakerArgon2Params))
	weak, err := New(rehashUsers, rehashSessions, rehashTokens, NoSecondFactors{}, weakOpts...)
	if err != nil {
		t.Fatalf("New (weak): %v", err)
	}
	const rehashEmail = "rehash@example.com"
	const rehashPass = "rehash-battery-staple"
	secret("the rehash address", rehashEmail)
	secret("the rehash password", rehashPass)
	rehashUser, _, rehashTok, err := weak.Register(ctx, rehashEmail, rehashPass, sweepRequestInfo)
	if err != nil {
		t.Fatalf("Register (rehash): %v", err)
	}
	secret("the rehash registration session token", rehashTok)
	verifyUserEmail(t, rehashUsers, rehashUser.ID)

	strong, err := New(rehashUsers, rehashSessions, rehashTokens, NoSecondFactors{}, base()...)
	if err != nil {
		t.Fatalf("New (strong): %v", err)
	}
	if _, err := strong.Login(ctx, rehashEmail, rehashPass, sweepRequestInfo); err != nil {
		t.Fatalf("Login (rehash): %v", err)
	}

	// The same upgrade, with the write failing.
	failMem := newMemUserStore()
	failUsers := &failUpdateUserStore{memUserStore: failMem}
	failWeak, err := New(failUsers, newMemSessionStore(), newMemTokenStore(), NoSecondFactors{}, base(WithArgon2Params(weakerArgon2Params))...)
	if err != nil {
		t.Fatalf("New (fail-weak): %v", err)
	}
	failUser, _, failTok, err := failWeak.Register(ctx, rehashEmail, rehashPass, sweepRequestInfo)
	if err != nil {
		t.Fatalf("Register (fail-rehash): %v", err)
	}
	secret("the failing-rehash session token", failTok)
	verifyUserEmail(t, failMem, failUser.ID)
	failUsers.updateErr = fmt.Errorf("store unavailable")
	failStrong, err := New(failUsers, newMemSessionStore(), newMemTokenStore(), NoSecondFactors{}, base()...)
	if err != nil {
		t.Fatalf("New (fail-strong): %v", err)
	}
	if _, err := failStrong.Login(ctx, rehashEmail, rehashPass, sweepRequestInfo); err != nil {
		t.Fatalf("Login (fail-rehash): %v — a failed rehash must not fail the login", err)
	}

	// Legacy (pre-NFKC) stored hash.
	legacy, legacyUsers, _, _ := newTestEnv(base()...)
	secret("the legacy password", nfkcCompatibilityForm)
	legacyUser := mustLegacyHashUser(t, legacy, legacyUsers, "legacy@example.com", nfkcCompatibilityForm)
	secret("the legacy address", "legacy@example.com")
	verifyUserEmail(t, legacyUsers, legacyUser.ID)
	if _, err := legacy.Login(ctx, "legacy@example.com", nfkcCompatibilityForm, sweepRequestInfo); err != nil {
		t.Fatalf("Login (legacy form): %v", err)
	}

	// --- lockout ----------------------------------------------------------
	lockoutOpts := []Option{WithArgon2Params(testArgon2Params), WithoutRateLimiting(), WithFailureLockout(2, time.Minute, time.Hour)}
	if sinkOpt != nil {
		lockoutOpts = append(lockoutOpts, WithEventSink(sinkOpt))
	}
	lock, lockUsers, _, _ := newTestEnv(lockoutOpts...)
	const lockEmail = "lock@example.com"
	const lockPass = "lockout-battery-staple"
	secret("the lockout address", lockEmail)
	secret("the lockout password", lockPass)
	lockUser := mustRegister(t, lock, lockEmail, lockPass)
	verifyUserEmail(t, lockUsers, lockUser.ID)
	for range 2 {
		if _, err := lock.Login(ctx, lockEmail, "wrong-battery-staple", sweepRequestInfo); err == nil {
			t.Fatal("Login with a wrong password unexpectedly succeeded")
		}
	}
	lockUserUntil(t, lockUsers, lockUser.ID, time.Now().Add(-time.Minute))
	if _, err := lock.Login(ctx, lockEmail, lockPass, sweepRequestInfo); err != nil {
		t.Fatalf("Login after the lockout window passed: %v", err)
	}

	// --- rate limiting ----------------------------------------------------
	limitedOpts := []Option{WithArgon2Params(testArgon2Params), WithLimiter(&fakeLimiter{denied: true})}
	if sinkOpt != nil {
		limitedOpts = append(limitedOpts, WithEventSink(sinkOpt))
	}
	limited, _, _, _ := newTestEnv(limitedOpts...)
	if _, err := limited.Login(ctx, aliceEmail, alicePass, sweepRequestInfo); err == nil {
		t.Fatal("Login through a denying limiter unexpectedly succeeded")
	}

	ipLimitedOpts := []Option{WithArgon2Params(testArgon2Params), WithLimiter(&ipOnlyDenyLimiter{})}
	if sinkOpt != nil {
		ipLimitedOpts = append(ipLimitedOpts, WithEventSink(sinkOpt))
	}
	ipLimited, _, _, _ := newTestEnv(ipLimitedOpts...)
	if _, err := ipLimited.Login(ctx, aliceEmail, alicePass, sweepRequestInfo); err == nil {
		t.Fatal("Login through an IP-denying limiter unexpectedly succeeded")
	}

	// --- HTTP middleware --------------------------------------------------
	web, _, _, _ := newTestEnv(base()...)
	ok := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	csrfReq := httptest.NewRequest(http.MethodPost, "https://app.example.com/x", nil)
	web.RequireCSRFToken(ok).ServeHTTP(httptest.NewRecorder(), csrfReq)

	sameOrigin := web.RequireSameOrigin([]string{"https://app.example.com"})(ok)
	crossSite := httptest.NewRequest(http.MethodPost, "https://app.example.com/x", nil)
	crossSite.Header.Set("Sec-Fetch-Site", "cross-site")
	sameOrigin.ServeHTTP(httptest.NewRecorder(), crossSite)

	badOrigin := httptest.NewRequest(http.MethodPost, "https://app.example.com/x", nil)
	badOrigin.Header.Set("Origin", "https://evil.example.com")
	sameOrigin.ServeHTTP(httptest.NewRecorder(), badOrigin)

	return sink, secrets
}
