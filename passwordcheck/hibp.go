package passwordcheck

import (
	"bufio"
	"context"
	"crypto/sha1" // #nosec G505 -- the HIBP range API is defined over SHA-1; the algorithm is theirs, and no collision property is relied on here
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultHIBPBaseURL is the Have I Been Pwned range endpoint [NewHIBP] queries
// unless [WithHIBPBaseURL] says otherwise. The five-character prefix sent to
// it is not a secret, but the response must not be tamperable — a downgraded
// or forged reply is a silent "this password is fine" — so this is https and
// should stay that way.
const DefaultHIBPBaseURL = "https://api.pwnedpasswords.com/range/"

// defaultHIBPTimeout bounds a single range lookup. Generous, because this
// only ever runs on a password-setting path (registration, change, reset)
// where a human is already waiting on an Argon2 hash, and never on a login.
const defaultHIBPTimeout = 5 * time.Second

// maxHIBPResponse caps how much of a range response is read. A padded
// response from the real API is around 30 KiB; anything approaching this
// limit is a misbehaving or hostile endpoint, and a password checker must not
// be a way to exhaust the memory of the process that trusted it.
const maxHIBPResponse = 1 << 20 // 1 MiB

// ErrMalformedResponse indicates a lookup could not complete because the
// range response held data this client could not parse. Today that means
// exactly one row shape: a suffix matching the password being checked whose
// count is not a parseable integer. A real API has never been observed to
// send one — this is corrupted-mirror or tampering-middlebox territory. A
// malformed row for some other suffix is unrelated noise and never produces
// this error; see [HIBP.lookup]'s doc comment.
//
// Under the fail-open default, an error wrapping this is treated the same as
// any other unreachable verdict: [HIBP.Check] returns nil and the password
// is accepted. Under [WithHIBPFailClosed], Check returns the wrapped error
// instead, and it is never [ErrCompromised] either way.
//
// This is exported so an application that wants custom handling for exactly
// this condition — without a new HIBPOption — can get it: wrap an *[HIBP] in
// your own [Checker], call its Check, and branch on
// errors.Is(err, ErrMalformedResponse) to, say, fail closed only on
// suspected tampering while still failing open on an ordinary transport
// error, or to alert on it distinctly.
var ErrMalformedResponse = errors.New("passwordcheck: malformed HIBP response for the queried range")

// HIBP checks passwords against the Have I Been Pwned range API using
// k-anonymity: only the first five hexadecimal digits of the password's SHA-1
// are ever sent. The service answers with every hash suffix it holds under
// that prefix — several hundred to a few thousand of them — and the match is
// made locally. The password, its full hash, and even the hash's suffix never
// leave the process.
//
// That property is the entire basis for querying a third party about a
// credential at all, so it is pinned by a test that inspects the whole
// outbound request — line, headers and body — and fails if any of those three
// values appears anywhere in it.
//
// # Availability
//
// This makes registration, password change, and password reset depend on
// another organisation's uptime. By default an HIBP that cannot get an answer
// — connection refused, timeout, 5xx, 429 — returns nil: the password is
// allowed through unchecked. [WithHIBPFailClosed] inverts that. See
// [NewHIBP] for why open is the default.
//
// # Case and padding
//
// Suffixes are compared case-insensitively, and rows with a count of zero are
// ignored: they are the fabricated padding entries the API adds when asked
// (which this client always does), and treating one as a hit would reject a
// perfectly good password.
//
// An HIBP is safe for concurrent use.
type HIBP struct {
	baseURL    string
	client     *http.Client
	timeout    time.Duration
	failClosed bool
}

// HIBPOption configures an [HIBP].
type HIBPOption func(*HIBP)

// WithHIBPBaseURL replaces [DefaultHIBPBaseURL]. The five-character prefix is
// appended directly to it, with exactly one "/" in between whether or not the
// URL already ends in one.
//
// Intended for tests and for a self-hosted mirror of the range data. Pointing
// it at an untrusted host hands that host a prefix of every password set in
// your application, and lets it answer "not breached" to everything.
func WithHIBPBaseURL(rawURL string) HIBPOption {
	return func(h *HIBP) { h.baseURL = strings.TrimRight(rawURL, "/") + "/" }
}

// WithHIBPTimeout bounds a single lookup (default 5s). It is applied to the
// request context, so it holds for a client supplied via
// [WithHIBPHTTPClient] as well as for the default one.
func WithHIBPTimeout(d time.Duration) HIBPOption {
	return func(h *HIBP) { h.timeout = d }
}

// WithHIBPHTTPClient supplies the *http.Client used for lookups — for a
// proxy, a custom transport, or connection pooling shared with the rest of an
// application. The client's own Timeout is respected in addition to
// [WithHIBPTimeout], not instead of it.
func WithHIBPHTTPClient(c *http.Client) HIBPOption {
	return func(h *HIBP) {
		if c != nil {
			h.client = c
		}
	}
}

// WithHIBPFailClosed makes a lookup that could not reach a verdict reject the
// password instead of allowing it: [HIBP.Check] returns the underlying
// transport or protocol error, which is deliberately not [ErrCompromised] —
// an unreachable service is not evidence about the password, and telling a
// user their password is breached when nobody actually looked is a lie that
// costs you their trust in the message.
//
// "Could not reach a verdict" also covers a response row that matches this
// password's suffix but whose count this client cannot parse: that row was
// supposed to be the answer, so under this option it is treated as an
// incomplete check and rejected, not silently read as "not found" (see
// lookup's doc comment and [ErrMalformedResponse]). A malformed row for some
// other suffix is unrelated noise and is still skipped either way.
//
// Choose this when policy genuinely requires that no password is ever set
// without a breach check having succeeded, and make sure the surrounding
// application turns the resulting error into "try again in a moment" rather
// than "choose a different password".
func WithHIBPFailClosed() HIBPOption {
	return func(h *HIBP) { h.failClosed = true }
}

// NewHIBP returns a [Checker] backed by the Have I Been Pwned range API.
//
// It is opt-in, and it fails open by default. Both of those are deliberate.
//
// Opt-in, because a library should not start making outbound requests on a
// user's behalf because they upgraded a dependency; the embedded
// [NewBlocklist] is the default instead, and it has no such property to
// declare.
//
// Fail open, because the alternative makes a third party's availability a
// hard dependency of your own registration and password-reset flows. When
// api.pwnedpasswords.com is unreachable, a fail-closed deployment cannot
// register a user or complete a password reset — including the reset someone
// is doing *because* they were just breached. Weighed against that, the cost
// of failing open is that a small number of passwords set during an outage go
// unchecked against this corpus, while still facing the length policy and the
// embedded blocklist. Availability of the recovery path wins. Operators whose
// policy says otherwise have [WithHIBPFailClosed], and should pair it with
// alerting on the error, because silently degrading to "nobody can change
// their password" is the failure mode to actually fear here.
//
// Typical use, alongside the local blocklist rather than instead of it:
//
//	sulis.WithPasswordChecker(passwordcheck.All(
//		passwordcheck.NewBlocklist(),
//		passwordcheck.NewHIBP(),
//	))
func NewHIBP(opts ...HIBPOption) *HIBP {
	h := &HIBP{
		baseURL: DefaultHIBPBaseURL,
		timeout: defaultHIBPTimeout,
	}
	for _, opt := range opts {
		opt(h)
	}
	if h.client == nil {
		h.client = &http.Client{}
	}
	return h
}

// Check looks password up in the breach corpus and returns [ErrCompromised]
// if it is present with a non-zero count.
//
// A lookup that cannot reach a verdict returns nil by default and the
// underlying error when [WithHIBPFailClosed] is set; either way that error is
// never [ErrCompromised]. A cancelled or expired ctx is an unreachable
// verdict like any other, so it too is subject to the fail-open/fail-closed
// choice. One such error, [ErrMalformedResponse], is exported specifically so
// callers can distinguish it from other unreachable-verdict causes with
// errors.Is.
func (h *HIBP) Check(ctx context.Context, password string) error {
	if password == "" {
		return nil
	}

	sum := sha1.Sum([]byte(password)) // #nosec G401 -- see the import comment: the range API's protocol is SHA-1 based
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	// The only part of the hash that is allowed to leave this process. The
	// suffix stays here and is compared against what comes back.
	prefix, suffix := full[:5], full[5:]

	found, err := h.lookup(ctx, prefix, suffix)
	if err != nil {
		if h.failClosed {
			return err
		}
		return nil
	}
	if found {
		return ErrCompromised
	}
	return nil
}

// lookup fetches the range for prefix and reports whether suffix appears in
// it with a non-zero count. It is the only function in this package that
// performs I/O, and prefix is the only password-derived value it is given —
// keeping it that way is what makes the k-anonymity property auditable by
// reading one function.
func (h *HIBP) lookup(ctx context.Context, prefix, suffix string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.baseURL+prefix, nil)
	if err != nil {
		return false, fmt.Errorf("passwordcheck: building range request: %w", err)
	}
	// Ask for padded responses: without this the number of rows returned
	// varies per prefix, so an observer who can see response sizes learns
	// something about which prefix was queried even over TLS.
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "sulis-passwordcheck")

	resp, err := h.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("passwordcheck: range lookup: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("passwordcheck: range lookup: unexpected status %s", resp.Status)
	}

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, maxHIBPResponse))
	for scanner.Scan() {
		rowSuffix, count, ok := strings.Cut(strings.TrimSpace(scanner.Text()), ":")
		if !ok {
			// A row this client does not understand is not a verdict either
			// way; skip it and keep looking. A genuine hit further down the
			// response must still be seen.
			continue
		}
		if !strings.EqualFold(rowSuffix, suffix) {
			continue
		}
		// Zero means a padding row: a fabricated suffix the API added because
		// of the Add-Padding header above.
		//
		// A count this client cannot parse at all is a different situation
		// once it lands on the one row that matches our suffix. A malformed
		// row for some *other* suffix is irrelevant noise — skipped by the
		// !strings.EqualFold continue above, scanning keeps going, and a
		// well-formed hit later in the response is still honored (see
		// TestHIBPToleratesMalformedRows). But this row was supposed to be
		// the answer, and a real API has never sent one unparsable, so there
		// is no expectation this branch fires in practice — the case it
		// guards is a misbehaving or compromised mirror corrupting exactly
		// the row that would have told us the truth. That is not "no
		// verdict" the way an unrelated bad row is; it is a check that could
		// not complete, and it is surfaced as an error from lookup instead
		// of silently skipped, so [HIBP.Check]'s existing fail-open/
		// fail-closed branching handles it exactly like a transport or
		// status failure: fail-open still accepts the password — the same
		// outcome as if the row had simply been absent (see
		// TestHIBPMalformedCountOnTheMatchingRowFailsOpen) — while
		// [WithHIBPFailClosed] rejects it as a check that did not complete,
		// not as a false "not found" (see
		// TestHIBPMalformedCountOnTheMatchingRowUnderFailClosed). The
		// returned error wraps [ErrMalformedResponse] so an application can
		// tell this case apart from an ordinary transport or status failure
		// via errors.Is, without a new HIBPOption.
		n, err := strconv.ParseInt(strings.TrimSpace(count), 10, 64)
		if err != nil {
			return false, fmt.Errorf("%w: row for matching suffix: %w", ErrMalformedResponse, err)
		}
		if n <= 0 {
			continue
		}
		return true, nil
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("passwordcheck: reading range response: %w", err)
	}
	return false, nil
}
