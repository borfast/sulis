package sulis_test

// Compiler-checked examples of the five most-copied flows, each written
// against the public API plus package memstore (the reference store that
// exists precisely for this). Every example calls out, in a comment, the
// security property it exercises — read those alongside the code, not just
// the code alone.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/borfast/sulis"
	"github.com/borfast/sulis/memstore"
	"github.com/borfast/sulis/passkey"
	"github.com/borfast/sulis/totp"
)

// totpSecondFactor adapts a totp.Store to sulis.SecondFactorChecker: a user
// has a second factor exactly when they have an active (verified) TOTP
// credential. A real application wires the equivalent against a
// passkey.Store, or both, and answers false only when neither is enrolled.
type totpSecondFactor struct{ store totp.Store }

func (c totpSecondFactor) HasSecondFactor(ctx context.Context, userID string) (bool, error) {
	_, err := c.store.GetActiveTOTP(ctx, userID)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, totp.ErrTOTPNotEnrolled):
		return false, nil
	default:
		// Fail closed: an unavailable checker must never silently downgrade
		// an account to a single factor. sulis.Sulis.Login already applies
		// this same rule around whatever HasSecondFactor returns here.
		return false, err
	}
}

// Example_passwordLoginWithTwoFactor shows a password login for an account
// enrolled in TOTP: the password is only the first factor, and no session
// exists until the second factor is verified too.
func Example_passwordLoginWithTwoFactor() {
	ctx := context.Background()

	totpStore := memstore.NewTOTPStore()
	auth, err := sulis.New(
		memstore.NewUserStore(), memstore.NewSessionStore(), memstore.NewTokenStore(),
		totpSecondFactor{store: totpStore},
	)
	if err != nil {
		fmt.Println("setup:", err)
		return
	}
	totpSvc, err := totp.NewService(totpStore, "ExampleApp")
	if err != nil {
		fmt.Println("setup:", err)
		return
	}

	ri := sulis.RequestInfo{IP: "203.0.113.5"}
	user, _, _, err := auth.Register(ctx, "kai@example.com", "correct-battery-staple", ri)
	if err != nil {
		fmt.Println("register:", err)
		return
	}

	// RequireVerifiedEmail defaults to true, so Login below would otherwise
	// refuse with ErrEmailNotVerified: Register's own signup session is
	// exempt, but a later Login is not. A real application verifies email
	// out of band (VerifyEmail, or a redeemed magic link); this stands in
	// for that having already happened.
	evToken, err := auth.CreateEmailVerificationToken(ctx, user.ID)
	if err != nil {
		fmt.Println("create verification token:", err)
		return
	}
	if _, err := auth.VerifyEmail(ctx, evToken); err != nil {
		fmt.Println("verify email:", err)
		return
	}

	// Seed an already-enrolled, already-confirmed TOTP credential directly
	// through the store, bypassing Service.Enroll/ConfirmEnrollment's code
	// exchange. That's fixture setup, not the flow this example
	// demonstrates: this whole example runs in well under a second, so a
	// code accepted at enrollment would still be the current time step's
	// code moments later at login, and Validate's replay check below would
	// correctly refuse it as a genuine reuse. Recording LastUsedCounter as
	// 0 here keeps that fixture out of the real check's way.
	secret, _, err := totpSvc.Enroll(ctx, user.ID, user.Email)
	if err != nil {
		fmt.Println("enroll:", err)
		return
	}
	pending, err := totpStore.GetPendingTOTP(ctx, user.ID)
	if err != nil {
		fmt.Println("pending:", err)
		return
	}
	if _, err := totpStore.ConfirmEnrollment(ctx, user.ID, pending.ID, 0); err != nil {
		fmt.Println("confirm:", err)
		return
	}

	// The password is the FIRST factor only.
	result, err := auth.Login(ctx, "kai@example.com", "correct-battery-staple", ri)
	if err != nil {
		fmt.Println("login:", err)
		return
	}

	// SECURITY: branch on NeedsSecondFactor. A non-nil *LoginResult is not
	// proof of a session by itself — treating it as "logged in" here would
	// defeat two-factor authentication entirely.
	if !result.NeedsSecondFactor {
		fmt.Println("expected a pending second factor")
		return
	}

	// The application collects a code from the user's authenticator app and
	// verifies it independently — sulis never sees the TOTP secret, and has
	// no way to check this itself.
	code, err := totpSvc.Generate(secret, time.Now())
	if err != nil {
		fmt.Println("generate:", err)
		return
	}
	if err := totpSvc.Validate(ctx, user.ID, code); err != nil {
		// totp.ErrTOTPInvalid, totp.ErrTOTPNotEnrolled, totp.ErrTOTPNotVerified,
		// totp.ErrTOTPReplayed, or totp.ErrTOTPRateLimited.
		fmt.Println("validate:", err)
		return
	}

	// Only now, with both factors verified, does a session exist.
	final, err := auth.CompleteTwoFactor(ctx, user.ID, result.PendingToken, ri)
	if err != nil {
		fmt.Println("complete:", err)
		return
	}

	fmt.Println("needs second factor:", result.NeedsSecondFactor)
	fmt.Println("session issued:", final.Session != nil)
	// Output:
	// needs second factor: true
	// session issued: true
}

// Example_magicLink shows requesting and redeeming a magic link for an
// address with no account yet: the account is created at redemption, and
// the mailbox proof it represents is treated as a full first factor.
func Example_magicLink() {
	ctx := context.Background()

	auth, err := sulis.New(
		memstore.NewUserStore(), memstore.NewSessionStore(), memstore.NewTokenStore(),
		sulis.NoSecondFactors{},
	)
	if err != nil {
		fmt.Println("setup:", err)
		return
	}

	// SECURITY (RequestInfo threading): the SAME RequestInfo is passed to
	// both calls below. It feeds the IP dimension of rate limiting for this
	// address — shared between creating and redeeming a link, so an
	// attacker can't dodge the budget by splitting the two requests across
	// different reported callers — and, on success, is copied onto the
	// minted Session's IP/UserAgent fields for the user's own "where you're
	// signed in" list. Pass the request actually in front of you each time,
	// not a zero value, if you want either of those to mean anything.
	ri := sulis.RequestInfo{IP: "203.0.113.15", UserAgent: "example-agent/1.0"}

	// No account exists for this address yet. CreateMagicLinkToken issues a
	// token without creating one; the user is created lazily at redemption.
	token, bindingNonce, err := auth.CreateMagicLinkToken(ctx, "sam@example.com", ri)
	if err != nil {
		fmt.Println("create:", err)
		return
	}

	// bindingNonce (non-empty by default) belongs in a short-lived,
	// HttpOnly cookie set on THIS response — never embedded in the emailed
	// link itself — and is read back from that cookie at redemption, so a
	// copy of the link forwarded to someone else arrives without it.
	// Passing it straight through here stands in for that round trip.
	result, err := auth.RedeemMagicLink(ctx, token, bindingNonce, ri)
	if err != nil {
		fmt.Println("redeem:", err)
		return
	}

	// No second factor is configured in this example, so a session exists
	// immediately. An account with one enrolled would get NeedsSecondFactor
	// set instead, exactly like Login — see the password + 2FA example.
	fmt.Println("session issued:", result.Session != nil)
	fmt.Println("session ip:", result.Session.IP)
	// Output:
	// session issued: true
	// session ip: 203.0.113.15
}

// Example_passkey shows the shape of a passkey registration and a passkey
// login: starting a ceremony, and what happens once its browser-signed
// response comes back. Finishing either ceremony needs a real, signed
// WebAuthn response from a browser and an authenticator, which this
// process-local example has no way to produce, so it stops at that
// boundary — the calls that would follow are named in comments instead of
// faked.
func Example_passkey() {
	ctx := context.Background()

	credentials := memstore.NewPasskeyStore()
	challenges := memstore.NewChallengeStore()
	svc, err := passkey.NewService(credentials, challenges, passkey.WebAuthnConfig{
		RPDisplayName: "Example App",
		RPID:          "example.com",
		RPOrigins:     []string{"https://example.com"},
	})
	if err != nil {
		fmt.Println("setup:", err)
		return
	}

	auth, err := sulis.New(
		memstore.NewUserStore(), memstore.NewSessionStore(), memstore.NewTokenStore(),
		sulis.NoSecondFactors{},
	)
	if err != nil {
		fmt.Println("setup:", err)
		return
	}

	ri := sulis.RequestInfo{IP: "203.0.113.9"}
	user, _, _, err := auth.Register(ctx, "morgan@example.com", "correct-battery-staple", ri)
	if err != nil {
		fmt.Println("register:", err)
		return
	}

	// RequireVerifiedEmail defaults to true, so IssueSessionUnchecked below
	// would otherwise refuse with ErrEmailNotVerified. See the equivalent
	// step in the password + 2FA example for why.
	evToken, err := auth.CreateEmailVerificationToken(ctx, user.ID)
	if err != nil {
		fmt.Println("create verification token:", err)
		return
	}
	if _, err := auth.VerifyEmail(ctx, evToken); err != nil {
		fmt.Println("verify email:", err)
		return
	}

	pu := &passkey.User{ID: []byte(user.ID), Name: user.Email, DisplayName: user.Email}

	// Registration: BeginRegistration hands the browser a challenge for its
	// authenticator to sign.
	if _, err := svc.BeginRegistration(ctx, pu); err != nil {
		fmt.Println("begin registration:", err)
		return
	}
	// The browser's navigator.credentials.create() response is later
	// handed, as raw bytes, to svc.FinishRegistrationResponse(ctx, pu,
	// body) — or FinishRegistration(ctx, pu, r) for an *http.Request — which
	// verifies the signature and saves the resulting *passkey.Credential.
	// A fixture stands in below for what that call would have stored, so
	// BeginLogin below has a credential to challenge.
	if err := credentials.SaveCredential(ctx, &passkey.Credential{
		ID:           "example-credential",
		UserID:       user.ID,
		CredentialID: []byte("example-credential-id"),
		PublicKey:    []byte("example-public-key"),
		CreatedAt:    time.Now(),
	}); err != nil {
		fmt.Println("seed credential:", err)
		return
	}

	// Login: BeginLogin hands the browser a challenge for whichever
	// registered credential it holds to sign.
	if _, _, err := svc.BeginLogin(ctx, pu); err != nil {
		fmt.Println("begin login:", err)
		return
	}
	// FinishLoginResponse(ctx, pu, ceremonyID, body) would verify the signed
	// assertion and return the Credential that produced it — rejecting a
	// sign-count anomaly with passkey.ErrCloneWarning, a signal of possible
	// cloning rather than a routine failure. sulis itself never checks a
	// WebAuthn signature; that verification is entirely the passkey
	// package's job. Once it succeeds, the caller — not sulis — is the one
	// asserting the factor passed:
	//
	// SECURITY (IssueSessionUnchecked's vouching semantics): this method
	// performs no credential check of its own. Calling it means THIS CODE
	// is vouching that userID just completed every factor the application
	// requires — here, a verified passkey assertion — not that sulis
	// independently confirmed it. Never call it on the strength of a bare
	// client claim.
	session, _, err := auth.IssueSessionUnchecked(ctx, user.ID, sulis.AuthMethodPasskey)
	if err != nil {
		fmt.Println("issue session:", err)
		return
	}

	fmt.Println("session method:", session.Method)
	// Output:
	// session method: passkey
}

// Example_passwordReset shows requesting and redeeming a password-reset
// token, including the response an unregistered address gets.
func Example_passwordReset() {
	ctx := context.Background()

	auth, err := sulis.New(
		memstore.NewUserStore(), memstore.NewSessionStore(), memstore.NewTokenStore(),
		sulis.NoSecondFactors{},
	)
	if err != nil {
		fmt.Println("setup:", err)
		return
	}

	ri := sulis.RequestInfo{IP: "203.0.113.11"}
	if _, _, _, err := auth.Register(ctx, "priya@example.com", "correct-battery-staple", ri); err != nil {
		fmt.Println("register:", err)
		return
	}

	// SECURITY (empty-token-means-unknown-email): an unregistered address
	// gets back ("", nil) — the same shape a real issuance takes from the
	// caller's side, and NOT distinguishable from it by error, return
	// value, or (CreatePasswordResetToken does the same generate-and-discard
	// work either way) the time it takes. A handler must render this
	// exactly like the known-address case ("if that address is registered,
	// we've sent a link") rather than branching on it — branching here is
	// exactly how a "forgot password" form turns into an account-existence
	// oracle.
	token, err := auth.CreatePasswordResetToken(ctx, "nobody@example.com", ri)
	if err != nil {
		fmt.Println("unexpected error:", err)
		return
	}
	fmt.Println("token for unknown address is empty:", token == "")

	token, err = auth.CreatePasswordResetToken(ctx, "priya@example.com", ri)
	if err != nil {
		fmt.Println("create token:", err)
		return
	}

	if err := auth.ResetPassword(ctx, token, "another-battery-staple"); err != nil {
		fmt.Println("reset:", err)
		return
	}

	_, err = auth.VerifyPassword(ctx, "priya@example.com", "another-battery-staple", ri)
	fmt.Println("new password verifies:", err == nil)
	// Output:
	// token for unknown address is empty: true
	// new password verifies: true
}

// Example_emailChange shows staging and confirming an email change, and the
// notification obligation that falls on the caller rather than on sulis.
func Example_emailChange() {
	ctx := context.Background()

	auth, err := sulis.New(
		memstore.NewUserStore(), memstore.NewSessionStore(), memstore.NewTokenStore(),
		sulis.NoSecondFactors{},
	)
	if err != nil {
		fmt.Println("setup:", err)
		return
	}

	ri := sulis.RequestInfo{IP: "203.0.113.13"}
	user, _, sessionToken, err := auth.Register(ctx, "old-address@example.com", "correct-battery-staple", ri)
	if err != nil {
		fmt.Println("register:", err)
		return
	}

	// sulis does not send mail. The raw token below is for delivery to the
	// NEW address, to prove control of it.
	//
	// SECURITY (notify the OLD address): the caller MUST ALSO notify the
	// OLD address that a change was requested — unconditionally, and with
	// no token attached, since it needs no confirmation. That notification
	// is how the account's rightful owner catches and can still undo a
	// takeover attempt (an attacker who set this in motion controls the new
	// address, never the old one) while the pending change hasn't taken
	// effect yet. Skipping it turns a recoverable takeover attempt into a
	// silent, completed one.
	token, err := auth.ChangeEmail(ctx, user.ID, "new-address@example.com")
	if err != nil {
		fmt.Println("change:", err)
		return
	}

	updated, err := auth.ConfirmEmailChange(ctx, token)
	if err != nil {
		fmt.Println("confirm:", err)
		return
	}

	// Confirming an email change revokes every session on the account: the
	// identity a still-live session was issued against has just changed.
	_, _, err = auth.ValidateSession(ctx, sessionToken)

	fmt.Println("live email:", updated.Email)
	fmt.Println("old session still valid:", err == nil)
	// Output:
	// live email: new-address@example.com
	// old session still valid: false
}
