package main

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/borfast/sulis"
	"github.com/borfast/sulis/totp"
)

// securityPageData feeds security.html.
type securityPageData struct {
	CSRFToken         string
	TOTPActive        bool
	RecoveryRemaining int
	Passkeys          []passkeyView
}

// passkeyView adapts a passkey.Credential for display on security.html: a
// label (falling back to a generic one when the credential was never named,
// since passkey itself never generates or validates Name) plus when it was
// created and last used.
type passkeyView struct {
	ID         string
	Label      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// handleSecurity shows the current state of a user's second factors: whether
// an authenticator app is active, how many recovery codes are left, and
// which passkeys are registered.
func (a *app) handleSecurity(w http.ResponseWriter, r *http.Request) {
	user, ok := sulis.UserFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	ctx := r.Context()

	_, totpErr := a.db.TOTPStore().GetActiveTOTP(ctx, user.ID)
	if totpErr != nil && !errors.Is(totpErr, totp.ErrTOTPNotEnrolled) {
		a.log.Error("checking totp status", "user_id", user.ID, "error", totpErr)
		a.render(w, http.StatusInternalServerError, "error", "Could not load your security settings.")
		return
	}
	totpActive := totpErr == nil

	remaining, err := a.recovery.Remaining(ctx, user.ID)
	if err != nil {
		a.log.Error("checking recovery codes remaining", "user_id", user.ID, "error", err)
		a.render(w, http.StatusInternalServerError, "error", "Could not load your security settings.")
		return
	}

	creds, err := a.db.PasskeyStore().GetCredentialsByUserID(ctx, user.ID)
	if err != nil {
		a.log.Error("listing passkeys", "user_id", user.ID, "error", err)
		a.render(w, http.StatusInternalServerError, "error", "Could not load your security settings.")
		return
	}
	passkeys := make([]passkeyView, 0, len(creds))
	for _, cred := range creds {
		label := cred.Name
		if label == "" {
			label = "Unnamed passkey"
		}
		passkeys = append(passkeys, passkeyView{
			ID: cred.ID, Label: label, CreatedAt: cred.CreatedAt, LastUsedAt: cred.LastUsedAt,
		})
	}

	token, cookie, err := a.auth.IssueCSRFToken()
	if err != nil {
		a.log.Error("issuing csrf token", "error", err)
		a.render(w, http.StatusInternalServerError, "error", "Something went wrong. Try again.")
		return
	}
	http.SetCookie(w, cookie)

	a.render(w, http.StatusOK, "security", securityPageData{
		CSRFToken: token, TOTPActive: totpActive, RecoveryRemaining: remaining, Passkeys: passkeys,
	})
}

// totpEnrollPageData feeds totp_enroll.html. Secret and URI are only
// populated right after a successful Enroll call: a failed confirmation
// re-renders this page without them, since the user already copied the
// secret into their authenticator app and only needs to retry the code
// (ConfirmEnrollment leaves the pending enrollment in place on a wrong
// code, so retrying does not require enrolling again).
type totpEnrollPageData struct {
	CSRFToken string
	Secret    string
	URI       string
	Error     string
}

// handleTOTPEnroll starts TOTP enrollment and shows the secret and otpauth
// URI as plain text, once, for the user to add to an authenticator app.
// Adding a second factor is step-up gated for the same reason changing the
// email address is: someone who walks up to an unlocked browser must not be
// able to attach their own authenticator to the account.
func (a *app) handleTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.log.Error("parsing totp-enroll form", "error", err)
		a.render(w, http.StatusBadRequest, "error", "Could not read that form submission.")
		return
	}
	user, ok := sulis.UserFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	session, _ := sulis.SessionFromContext(r.Context())
	if !a.requireRecentAuth(w, r, session) {
		return
	}
	// Echoed straight back, like handleLogin does: the double-submit cookie
	// this token pairs with is still on the browser and still valid.
	csrfToken := r.FormValue(sulis.CSRFFormField)

	secret, uri, err := a.totp.Enroll(r.Context(), user.ID, user.Email)
	if err != nil {
		a.log.Error("enrolling totp", "user_id", user.ID, "error", err)
		a.render(w, http.StatusUnprocessableEntity, "error",
			"Could not start enrollment. You may already have an authenticator app enabled.")
		return
	}

	a.render(w, http.StatusOK, "totp_enroll", totpEnrollPageData{
		CSRFToken: csrfToken, Secret: secret, URI: uri,
	})
}

// handleTOTPConfirm verifies the first code from a freshly enrolled
// authenticator app and, if it matches, promotes the pending enrollment to
// active so future logins demand it as a second factor.
func (a *app) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.log.Error("parsing totp-confirm form", "error", err)
		a.render(w, http.StatusBadRequest, "error", "Could not read that form submission.")
		return
	}
	user, ok := sulis.UserFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	code := r.FormValue("code")
	csrfToken := r.FormValue(sulis.CSRFFormField)

	if err := a.totp.ConfirmEnrollment(r.Context(), user.ID, code); err != nil {
		// ConfirmEnrollment's own doc comment warns against treating
		// ErrTOTPNotEnrolled here as "you are not enrolled", but every
		// distinct cause (wrong code, rate limited, racing enrollment,
		// retried confirm) reads identically to the user either way, so one
		// generic message covers all of them.
		a.log.Error("confirming totp enrollment", "user_id", user.ID, "error", err)
		a.render(w, http.StatusUnprocessableEntity, "totp_enroll", totpEnrollPageData{
			CSRFToken: csrfToken, Error: "That code is invalid or has expired. Try again.",
		})
		return
	}

	http.Redirect(w, r, "/security", http.StatusSeeOther)
}

// handleTOTPDisable removes a user's TOTP enrollment. It is step-up gated:
// taking a second factor off an account is exactly what an attacker holding
// a stolen session would want to do first. If no other second factor (a
// passkey) is left, it also purges any leftover recovery codes:
// recovery.Service.Disable's doc comment names exactly this moment as the
// purge hook, since recovery codes back up a real factor rather than
// standing on their own.
func (a *app) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.log.Error("parsing totp-disable form", "error", err)
		a.render(w, http.StatusBadRequest, "error", "Could not read that form submission.")
		return
	}
	user, ok := sulis.UserFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	session, _ := sulis.SessionFromContext(r.Context())
	if !a.requireRecentAuth(w, r, session) {
		return
	}

	if err := a.totp.Unenroll(r.Context(), user.ID); err != nil {
		a.log.Error("unenrolling totp", "user_id", user.ID, "error", err)
		a.render(w, http.StatusInternalServerError, "error", "Could not disable the authenticator app.")
		return
	}

	creds, err := a.db.PasskeyStore().GetCredentialsByUserID(r.Context(), user.ID)
	if err != nil {
		a.log.Error("checking remaining passkeys", "user_id", user.ID, "error", err)
	} else if len(creds) == 0 {
		if err := a.recovery.Disable(r.Context(), user.ID); err != nil {
			a.log.Error("disabling recovery codes", "user_id", user.ID, "error", err)
		}
	}

	http.Redirect(w, r, "/security", http.StatusSeeOther)
}

// recoveryCodesPageData feeds recovery_codes.html.
type recoveryCodesPageData struct {
	Codes []string
}

// handleRecoveryGenerate issues a fresh set of recovery codes, replacing any
// existing ones, and shows the plaintext codes once: Generate does not
// return them again afterward. It is step-up gated because it both shows
// codes that bypass every other factor and invalidates the set the real
// owner wrote down.
func (a *app) handleRecoveryGenerate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.log.Error("parsing recovery-generate form", "error", err)
		a.render(w, http.StatusBadRequest, "error", "Could not read that form submission.")
		return
	}
	user, ok := sulis.UserFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	session, _ := sulis.SessionFromContext(r.Context())
	if !a.requireRecentAuth(w, r, session) {
		return
	}

	codes, err := a.recovery.Generate(r.Context(), user.ID)
	if err != nil {
		a.log.Error("generating recovery codes", "user_id", user.ID, "error", err)
		a.render(w, http.StatusInternalServerError, "error", "Could not generate recovery codes.")
		return
	}

	a.render(w, http.StatusOK, "recovery_codes", recoveryCodesPageData{Codes: codes})
}

// secondFactorPageData feeds second_factor.html.
type secondFactorPageData struct {
	CSRFToken   string
	Error       string
	UseRecovery bool
}

// handleSecondFactorForm shows the second-factor form. It redirects to
// /login straight away if the pending-login cookie is missing: there is
// nothing to complete.
func (a *app) handleSecondFactorForm(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie(pendingTokenCookie); err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	token, cookie, err := a.auth.IssueCSRFToken()
	if err != nil {
		a.log.Error("issuing csrf token", "error", err)
		a.render(w, http.StatusInternalServerError, "error", "Something went wrong. Try again.")
		return
	}
	http.SetCookie(w, cookie)
	a.render(w, http.StatusOK, "second_factor", secondFactorPageData{CSRFToken: token})
}

// handleSecondFactor completes a login that needed a second factor. The
// user ID it checks the code against comes from the server-side pending
// entry the token names, never from the request: a client that can invent a
// pending token must not be able to pick which account's factor is tested.
// Once that lookup succeeds it verifies the submitted TOTP or recovery code
// itself, then hands the pending token to CompleteTwoFactor. The entry and
// the cookie are both gone on every outcome, success or failure, since a
// pending login is meant to be resolved by exactly one submission.
func (a *app) handleSecondFactor(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.log.Error("parsing second-factor form", "error", err)
		a.render(w, http.StatusBadRequest, "error", "Could not read that form submission.")
		return
	}

	csrfToken := r.FormValue(sulis.CSRFFormField)
	code := r.FormValue("code")
	useRecovery := r.FormValue("use_recovery") != ""

	tokenCookie, tokenErr := r.Cookie(pendingTokenCookie)
	a.clearPendingCookie(w)

	var (
		pendingToken string
		userID       string
		known        bool
	)
	if tokenErr == nil {
		pendingToken = tokenCookie.Value
		userID, known = a.pending2FA.take(pendingToken)
	}
	if !known {
		// A missing, expired, or invented token names no pending login, so
		// there is no account to check a code against and nothing below
		// runs. This is also what stops an invented cookie from being used
		// to test codes against an account of the attacker's choosing.
		a.render(w, http.StatusUnprocessableEntity, "second_factor", secondFactorPageData{
			CSRFToken: csrfToken, Error: "Your login attempt expired. Log in again.",
		})
		return
	}

	var verifyErr error
	if useRecovery {
		_, verifyErr = a.recovery.Consume(r.Context(), userID, code)
	} else {
		verifyErr = a.totp.Validate(r.Context(), userID, code)
	}
	if verifyErr != nil {
		// Every rejection reason (wrong code, replayed code, rate limited,
		// not enrolled) reads identically to the user: telling them apart
		// would leak which of those applies to this account.
		a.log.Error("verifying second factor", "user_id", userID, "error", verifyErr)
		a.render(w, http.StatusUnprocessableEntity, "second_factor", secondFactorPageData{
			CSRFToken: csrfToken, Error: "That code is invalid. Log in again.", UseRecovery: useRecovery,
		})
		return
	}

	result, err := a.auth.CompleteTwoFactor(r.Context(), userID, pendingToken, requestInfo(r))
	if err != nil {
		a.log.Error("completing two-factor login", "user_id", userID, "error", err)
		a.render(w, http.StatusUnprocessableEntity, "second_factor", secondFactorPageData{
			CSRFToken: csrfToken, Error: "That code is invalid. Log in again.", UseRecovery: useRecovery,
		})
		return
	}

	a.handleLoginResult(w, r, result)
}

// clearPendingCookie removes the pending-2FA cookie, mirroring how
// handleLoginResult sets it (same Path, HttpOnly, Secure, SameSite) so the
// browser actually deletes it instead of keeping a stale value under
// slightly different attributes.
func (a *app) clearPendingCookie(w http.ResponseWriter) {
	// #nosec G124 -- HttpOnly and SameSite are set; Secure is computed from
	// the -tls flag rather than a literal, which this rule's static check
	// for `Secure: true` does not recognize.
	http.SetCookie(w, &http.Cookie{
		Name: pendingTokenCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: strings.HasPrefix(a.baseURL, "https://"),
		SameSite: http.SameSiteLaxMode,
	})
}
