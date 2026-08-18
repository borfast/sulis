package sulis

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"time"
)

// Session represents a server-side authentication session.
type Session struct {
	ID     string
	UserID string
	// TokenHash is the SHA-256 hash of the session token. The raw token is
	// never a field on this struct: it is returned beside the *Session at
	// issue time and nowhere else, so no store can persist it by accident.
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
	// AuthenticatedAt is when the credential behind this session was last
	// proven — at issuance, and again on every successful ReAuthenticate.
	// RequireRecentAuth compares it against a caller-supplied maxAge to gate
	// security-sensitive operations (enrolling or replacing a second
	// factor, removing a passkey, disabling 2FA, changing email,
	// regenerating recovery codes — see the README) behind more than a
	// bare, possibly hours-old session. A session issued before this field
	// existed reads back as the zero time, which is always older than any
	// maxAge, so RequireRecentAuth fails closed on it rather than treating
	// an absent stamp as fresh.
	AuthenticatedAt time.Time
	// Method records which credential last authenticated this session —
	// set at issuance from the AuthMethod the caller vouches for (or, for
	// IssueSession, the one recorded on the Authentication proof) and left
	// untouched by ReAuthenticate, which refreshes AuthenticatedAt only.
	Method AuthMethod
	// LastSeenAt records when this session was last used — stamped at
	// issuance, and refreshed by ValidateSession via TouchSession while the
	// session stays active. It is throttled, not written on every call: see
	// sessionTouchInterval's doc comment for why. Useful for a
	// device-management "last active" column; do not read it as
	// precise-to-the-request.
	LastSeenAt time.Time
	// IdleExpiresAt is the deadline past which ValidateSession rejects this
	// session with ErrSessionExpired even though ExpiresAt has not been
	// reached yet — an idle-timeout, refreshed alongside LastSeenAt on the
	// same throttled cadence. Nil means idle expiry is disabled for this
	// session, which is the case for every session unless WithIdleTimeout
	// is configured (the default).
	IdleExpiresAt *time.Time
	// IP and UserAgent are copied from the RequestInfo the issuing call
	// received, so a "where you're signed in" screen can render something
	// recognizable ("Chrome on a Lisbon IP", roughly). Only the
	// issuance paths that take a RequestInfo populate them:
	// Register/Login/RedeemMagicLink/CompleteTwoFactor. IssueSession and
	// IssueSessionUnchecked have no RequestInfo in their Appendix A
	// signatures, so sessions minted through them carry the zero value —
	// see the PROGRESS.md Decisions row for T503.
	IP        string
	UserAgent string
	Metadata  map[string]any
}

// SessionStore defines the persistence operations for sessions.
//
// A store MUST NOT share mutable state with its callers in either direction.
// Metadata is a map, so copying a *Session with a plain struct assignment
// copies a map header rather than the map, leaving the caller holding a live
// handle on the stored session — and a session a caller can rewrite outside
// CreateSession is a session whose UserID a caller can rewrite. Copy the map
// (one level is enough) when storing a session and when returning one. Stores
// that reconstruct rows from a database read get this for free; in-memory ones
// do not. storetest.RunSessionStore checks it.
type SessionStore interface {
	CreateSession(ctx context.Context, session *Session) error
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error)

	// ListUserSessions returns every session belonging to userID, in any
	// order. Matching nothing is not an error — an empty (possibly nil)
	// slice and a nil error.
	//
	// Returned sessions MUST be independent copies, the same no-aliasing
	// rule CreateSession/GetSessionByTokenHash already follow: a caller
	// mutating an entry in the returned slice must never reach the stored
	// row. This includes TokenHash — this method returns it exactly as
	// stored, the same as GetSessionByTokenHash does. Stripping it to ""
	// before it reaches an application is Sulis.ListUserSessions's job,
	// not this method's.
	ListUserSessions(ctx context.Context, userID string) ([]Session, error)

	// DeleteSession removes the session identified by id if it belongs to
	// userID. The membership check and the removal MUST happen as a
	// single atomic operation scoped to both columns:
	//
	//	DELETE FROM sessions WHERE id = ? AND user_id = ?
	//
	// Zero rows affected — whether id does not exist at all, or exists
	// but belongs to a different user — MUST return ErrSessionNotFound
	// rather than succeeding silently. This is what makes cross-user
	// revocation impossible through RevokeSession: it passes the
	// caller's own userID, so guessing or leaking another user's session
	// ID never deletes anything.
	DeleteSession(ctx context.Context, userID, id string) error

	DeleteUserSessions(ctx context.Context, userID string) error

	// DeleteUserSessionsExcept removes every session belonging to userID
	// except the one identified by keepSessionID, as a single operation:
	//
	//	DELETE FROM sessions WHERE user_id = ? AND id <> ?
	//
	// This is the "sign out everywhere else" primitive: a device-management
	// UI keeps the session the request making the call is itself using and
	// revokes the rest. keepSessionID naming a session that does not exist,
	// or one belonging to a different user, is not an error — every OTHER
	// session for userID is removed regardless, matching
	// DeleteUserSessions's "matching nothing is not an error" behavior for
	// the degenerate all-sessions case. There is no Sulis-level wrapper for
	// this method (see the PROGRESS.md Decisions row): Appendix A does not
	// name one, and the facade-level path for the same outcome is
	// ListUserSessions plus a RevokeSession per entry.
	DeleteUserSessionsExcept(ctx context.Context, userID, keepSessionID string) error

	CleanExpired(ctx context.Context) error

	// UpdateAuthenticatedAt stamps the session identified by id with at,
	// leaving every other field (including ExpiresAt and Method) untouched:
	//
	//	UPDATE sessions SET authenticated_at = ? WHERE id = ?
	//
	// Zero rows affected — id does not exist — MUST return
	// ErrSessionNotFound. This is the write path behind ReAuthenticate: it
	// refreshes how recently a session's owner last proved their
	// credential, without minting a new session or rotating its token, so
	// a subsequent RequireRecentAuth call passes immediately afterward.
	//
	// It is deliberately its own method rather than an extra parameter on
	// TouchSession's session-liveness "last seen" touch below: a step-up
	// re-authentication and a liveness heartbeat are different events with
	// different callers and different frequencies, and folding them into
	// one call would make a caller that means to refresh only one of the
	// two silently refresh both.
	UpdateAuthenticatedAt(ctx context.Context, id string, at time.Time) error

	// TouchSession stamps the session identified by id with a fresh
	// lastSeen and idleExpires, leaving every other column (ExpiresAt,
	// TokenHash, AuthenticatedAt, Method, IP, UserAgent, ...) untouched:
	//
	//	UPDATE sessions SET last_seen_at = ?, idle_expires_at = ? WHERE id = ?
	//
	// idleExpires is nil whenever idle expiry is disabled (WithIdleTimeout
	// not configured, the default). A nil idleExpires MUST be written as
	// SQL NULL, clearing any previously-stored value — an application that
	// enables idle expiry and later disables it again must not have a
	// stale deadline linger and silently start enforcing itself once more.
	//
	// Zero rows affected — id does not exist — MUST return
	// ErrSessionNotFound. This is the write path behind
	// Sulis.ValidateSession's liveness touch, and it is deliberately
	// throttled rather than called on every validation — see
	// sessionTouchInterval's doc comment for the cost rationale.
	TouchSession(ctx context.Context, id string, lastSeen time.Time, idleExpires *time.Time) error
}

// sessionTouchIntervalDivisor and defaultSessionTouchInterval configure how
// often ValidateSession writes a fresh LastSeenAt/IdleExpiresAt via
// TouchSession, via sessionTouchInterval below.
//
// Writing on every validated request would mean a store write on every
// authenticated request an application serves — for an app with an
// authenticated endpoint behind most routes, that is a write per request,
// dwarfing every other store call this package makes on the hot path.
// Throttling means LastSeenAt is only ever off by at most this interval,
// which is a fine trade: nobody needs "seen 3ms ago" precision on a
// device-management screen.
//
// When WithIdleTimeout is configured, the interval is derived from it
// (IdleTimeout / sessionTouchIntervalDivisor) rather than fixed, so a short
// idle timeout is still touched often enough that a session making steady,
// well-inside-the-timeout requests never falsely idle-expires: the stored
// IdleExpiresAt is never more than one interval behind what a
// write-every-request implementation would have recorded, i.e. never stale
// by more than IdleTimeout/sessionTouchIntervalDivisor. Without idle expiry
// configured there is nothing to keep ahead of, so a fixed, generous
// interval bounds LastSeenAt staleness purely for the device-management use
// case.
const (
	sessionTouchIntervalDivisor = 4
	defaultSessionTouchInterval = 5 * time.Minute
)

// sessionTouchInterval returns the minimum gap ValidateSession leaves
// between two TouchSession writes for the same session. See the constants
// above for the cost rationale.
func (s *Sulis) sessionTouchInterval() time.Duration {
	if s.cfg.IdleTimeout > 0 {
		return s.cfg.IdleTimeout / sessionTouchIntervalDivisor
	}
	return defaultSessionTouchInterval
}

// idleExpiresAt returns the idle-expiry deadline for a session touched (or
// newly created) at at, or nil if idle expiry is disabled — WithIdleTimeout
// not configured, the default.
func (s *Sulis) idleExpiresAt(at time.Time) *time.Time {
	if s.cfg.IdleTimeout <= 0 {
		return nil
	}
	deadline := at.Add(s.cfg.IdleTimeout)
	return &deadline
}

// ListUserSessions returns every session belonging to userID, most useful
// for a "where you're signed in" device-management screen: each entry
// carries CreatedAt, LastSeenAt, AuthenticatedAt, Method, IP, and UserAgent,
// enough for an application to render something like "Chrome, last active 2
// hours ago" and let the user revoke anything they don't recognize via
// RevokeSession.
//
// TokenHash is stripped to "" on every returned Session — this is the
// security property the task that added this method exists for. The store
// method behind this (SessionStore.ListUserSessions) returns TokenHash
// exactly as stored, the same as GetSessionByTokenHash; blanking it before
// it ever reaches a caller happens here, once, rather than depending on
// every current and future listing path remembering to do it themselves.
func (s *Sulis) ListUserSessions(ctx context.Context, userID string) ([]Session, error) {
	sessions, err := s.sessions.ListUserSessions(ctx, userID)
	if err != nil {
		return nil, err
	}
	for i := range sessions {
		sessions[i].TokenHash = ""
	}
	return sessions, nil
}

// RefreshSession rotates session's token: it retires session's old row
// first and, only if that succeeds, mints a new session row with a new ID
// and a new raw token, extending ExpiresAt from now while carrying UserID,
// Method, AuthenticatedAt, CreatedAt, IP, UserAgent, and Metadata forward
// unchanged.
//
// AuthenticatedAt is preserved deliberately: a refresh is a liveness/
// rotation operation, not a fresh authentication proof, and must not reset
// the step-up clock RequireRecentAuth reads.
//
// The returned *Session has a different ID and TokenHash than session —
// this is a new store row, not an in-place update to the one passed in.
// Deliberate: SessionStore has no primitive to rewrite a session's token
// and expiry in place (TouchSession and UpdateAuthenticatedAt each update
// a narrow, different pair of columns), so building a fresh row from the
// existing CreateSession/DeleteSession pair avoids adding a third
// narrow-purpose update method to the store contract for the sake of one
// caller. Rotating the ID is also a small defense-in-depth win: a
// previously-leaked session ID stops referring to anything live the moment
// this call succeeds.
//
// The OLD row is deleted FIRST, and RefreshSession only proceeds to mint a
// new one if that delete actually succeeds — this is a fail-closed liveness
// check, not an optimization. Without it, a caller holding a stale *Session
// obtained before a revocation (RevokeSession, RevokeAllSessions, or a
// device evicted through the ListUserSessions screen this package builds)
// could call RefreshSession and mint a brand-new working session anyway,
// un-evicting themselves: CreateSession never consults whether the old row
// still exists, so a create-then-delete order with the delete's result
// discarded lets exactly that happen. DeleteSession returning
// ErrSessionNotFound (the old row is already gone) is therefore propagated
// verbatim, before any new row is created. This is the same "burn first,
// validate second" direction consumeToken and passkey's ConsumeChallenge
// already take ("failures burn the token") and the reason DeleteSession's
// own ownership-scoped delete-with-error-on-zero-rows exists in the first
// place: the cost is a crash window between the delete and the create
// logging the caller out, which is the safe direction to fail in, not an
// account left refreshable after it should not be.
//
// For the same reason, this reloads the user and checks accountStatus
// before minting, closing the one remaining way a stale *Session could
// still refresh into a live one: DisableUser's own session revocation could
// legitimately fail (store error) while its DisabledAt stamp still lands,
// leaving the old row intact for DeleteSession to happily remove above —
// without this check, that would be enough to mint a fresh session for a
// disabled account, since a newly-minted row never passes back through
// ValidateSession's own DisabledAt gate. Both checks run after the delete
// succeeds, so a disabled-account refresh still burns the caller's old
// session on its way to ErrAccountDisabled, consistent with the fail-closed
// direction above.
//
// RefreshSession takes no RequestInfo — Appendix A gives it none — so IP
// and UserAgent are carried forward from the caller's (possibly stale)
// in-memory session rather than re-derived from the current request. A
// long-lived session refreshed repeatedly from a new IP can therefore show
// a stale IP/UserAgent in a "where you're signed in" listing even while
// LastSeenAt looks current; see the PROGRESS.md Decisions row.
func (s *Sulis) RefreshSession(ctx context.Context, session *Session) (*Session, string, error) {
	if err := s.sessions.DeleteSession(ctx, session.UserID, session.ID); err != nil {
		return nil, "", err
	}

	user, err := s.users.GetUserByID(ctx, session.UserID)
	if err != nil {
		return nil, "", err
	}
	if err := s.accountStatus(user); err != nil {
		return nil, "", err
	}

	token, err := generateSessionToken(s.cfg.SessionTokenBytes)
	if err != nil {
		return nil, "", err
	}

	now := time.Now()
	fresh := &Session{
		ID:              generateID(),
		UserID:          session.UserID,
		TokenHash:       hashSessionToken(token),
		ExpiresAt:       now.Add(s.cfg.SessionDuration),
		CreatedAt:       session.CreatedAt,
		AuthenticatedAt: session.AuthenticatedAt,
		Method:          session.Method,
		LastSeenAt:      now,
		IdleExpiresAt:   s.idleExpiresAt(now),
		IP:              session.IP,
		UserAgent:       session.UserAgent,
	}
	if session.Metadata != nil {
		fresh.Metadata = maps.Clone(session.Metadata)
	}

	if err := s.sessions.CreateSession(ctx, fresh); err != nil {
		return nil, "", err
	}

	// SessionID is the NEW row's ID. A refresh is a rotation, not a fresh
	// authentication, so this is deliberately not EventSessionIssued: a sink
	// counting sign-ins must not count rotations among them.
	//
	// RequestInfo is left zero for the same reason ValidateSession's expiry
	// events leave it zero (see emitSessionEnded): RefreshSession takes
	// none, and the IP/UserAgent carried forward on the session describe the
	// request that issued it, possibly long ago and somewhere else.
	s.emit(ctx, Event{
		Kind:      EventSessionRefreshed,
		UserID:    fresh.UserID,
		SessionID: fresh.ID,
		Metadata:  meta(string(MetaMethod), string(fresh.Method)),
	})

	return fresh, token, nil
}

// generateSessionToken creates a cryptographically random session token.
func generateSessionToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("sulis: generating session token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func hashSessionToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
