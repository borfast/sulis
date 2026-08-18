package passwordcheck

import (
	"context"
	"crypto/sha1" // #nosec G505 -- the HIBP range API is defined over SHA-1; the choice is theirs, not ours
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// hibpTestPassword is the password every test in this file looks up, along
// with its SHA-1 split the way the range API splits it.
const hibpTestPassword = "correct-battery-staple"

func hibpHash(password string) (full, prefix, suffix string) {
	sum := sha1.Sum([]byte(password)) // #nosec G401 -- see the import comment
	full = strings.ToUpper(hex.EncodeToString(sum[:]))
	return full, full[:5], full[5:]
}

// TestHIBPSendsOnlyTheSHA1Prefix is the k-anonymity proof, and the single
// most important test in this package: the whole reason a breach lookup can
// be made against a third party at all is that the third party never learns
// the password or even its full hash. If this test can pass while the client
// leaks either, the feature is a credential exfiltration channel wearing a
// security feature's name.
func TestHIBPSendsOnlyTheSHA1Prefix(t *testing.T) {
	full, prefix, suffix := hibpHash(hibpTestPassword)

	var captured *http.Request
	var capturedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		capturedBody = string(b)
		captured = r.Clone(context.Background())
		captured.URL = r.URL
		_, _ = io.WriteString(w, "0000000000000000000000000000000000A:3\r\n")
	}))
	defer srv.Close()

	h := NewHIBP(WithHIBPBaseURL(srv.URL + "/range/"))
	if err := h.Check(context.Background(), hibpTestPassword); err != nil {
		t.Fatalf("Check: %v", err)
	}

	if captured == nil {
		t.Fatal("the client made no request at all")
	}
	if captured.Method != http.MethodGet {
		t.Errorf("method = %q, want GET", captured.Method)
	}
	if got, want := captured.URL.Path, "/range/"+prefix; got != want {
		t.Errorf("request path = %q, want %q", got, want)
	}
	if captured.URL.RawQuery != "" {
		t.Errorf("request carried a query string %q; the range API takes none, and anything added there is data the third party did not need", captured.URL.RawQuery)
	}
	if capturedBody != "" {
		t.Errorf("request body = %q, want empty", capturedBody)
	}

	// Nothing anywhere in the request — line, headers, or body — may contain
	// the password, the full hash, or the hash's suffix.
	var sb strings.Builder
	sb.WriteString(captured.URL.String())
	sb.WriteString("\n")
	for name, values := range captured.Header {
		sb.WriteString(name)
		sb.WriteString(": ")
		sb.WriteString(strings.Join(values, ","))
		sb.WriteString("\n")
	}
	sb.WriteString(capturedBody)
	wire := sb.String()

	for _, secret := range []struct {
		name  string
		value string
	}{
		{"the password", hibpTestPassword},
		{"the full SHA-1 (upper case)", full},
		{"the full SHA-1 (lower case)", strings.ToLower(full)},
		{"the SHA-1 suffix (upper case)", suffix},
		{"the SHA-1 suffix (lower case)", strings.ToLower(suffix)},
	} {
		if strings.Contains(wire, secret.value) {
			t.Errorf("the outbound request leaked %s (%q): %s", secret.name, secret.value, wire)
		}
	}

	if len(prefix) != 5 {
		t.Fatalf("prefix %q is %d characters, want 5", prefix, len(prefix))
	}
}

func TestHIBPRejectsAPasswordPresentInTheRange(t *testing.T) {
	_, _, suffix := hibpHash(hibpTestPassword)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "0000000000000000000000000000000000A:1\r\n"+suffix+":42\r\n")
	}))
	defer srv.Close()

	h := NewHIBP(WithHIBPBaseURL(srv.URL + "/range/"))
	if err := h.Check(context.Background(), hibpTestPassword); !errors.Is(err, ErrCompromised) {
		t.Fatalf("Check = %v, want ErrCompromised", err)
	}
}

func TestHIBPAcceptsAPasswordAbsentFromTheRange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "0000000000000000000000000000000000A:1\r\n0000000000000000000000000000000000B:9\r\n")
	}))
	defer srv.Close()

	h := NewHIBP(WithHIBPBaseURL(srv.URL + "/range/"))
	if err := h.Check(context.Background(), hibpTestPassword); err != nil {
		t.Fatalf("Check = %v, want nil", err)
	}
}

// TestHIBPMatchesSuffixCaseInsensitively guards against a mismatch in hex
// case between what we compute and what the API returns.
func TestHIBPMatchesSuffixCaseInsensitively(t *testing.T) {
	_, _, suffix := hibpHash(hibpTestPassword)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.ToLower(suffix)+":7\n")
	}))
	defer srv.Close()

	h := NewHIBP(WithHIBPBaseURL(srv.URL + "/range/"))
	if err := h.Check(context.Background(), hibpTestPassword); !errors.Is(err, ErrCompromised) {
		t.Fatalf("Check = %v, want ErrCompromised", err)
	}
}

// TestHIBPIgnoresPaddingEntries covers the padded response mode the client
// asks for: padding rows are fabricated suffixes with a count of zero, and
// treating one as a hit would reject a perfectly good password.
func TestHIBPIgnoresPaddingEntries(t *testing.T) {
	_, _, suffix := hibpHash(hibpTestPassword)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, suffix+":0\r\n")
	}))
	defer srv.Close()

	h := NewHIBP(WithHIBPBaseURL(srv.URL + "/range/"))
	if err := h.Check(context.Background(), hibpTestPassword); err != nil {
		t.Fatalf("a zero-count padding row was treated as a breach hit: %v", err)
	}
}

func TestHIBPRequestsPadding(t *testing.T) {
	var header string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Get("Add-Padding")
		_, _ = io.WriteString(w, "")
	}))
	defer srv.Close()

	h := NewHIBP(WithHIBPBaseURL(srv.URL + "/range/"))
	if err := h.Check(context.Background(), hibpTestPassword); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if header != "true" {
		t.Errorf("Add-Padding header = %q, want %q — without it the response length itself narrows the candidate set", header, "true")
	}
}

// TestHIBPFailsOpenByDefault and TestHIBPFailsClosedWhenConfigured are the
// two halves of the availability decision: reachability of a third party
// must not silently become a hard dependency of registration and password
// reset, but an operator whose policy says otherwise must be able to say so.
func TestHIBPFailsOpenByDefault(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		stop    bool
	}{
		{name: "connection refused", stop: true, handler: func(http.ResponseWriter, *http.Request) {}},
		{name: "server error", handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }},
		{name: "rate limited", handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTooManyRequests) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			if tc.stop {
				srv.Close() // nothing is listening on this address any more
			}

			h := NewHIBP(WithHIBPBaseURL(srv.URL+"/range/"), WithHIBPTimeout(2*time.Second))
			if err := h.Check(context.Background(), hibpTestPassword); err != nil {
				t.Fatalf("Check = %v, want nil (fail open)", err)
			}
		})
	}
}

func TestHIBPFailsClosedWhenConfigured(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		stop    bool
	}{
		{name: "connection refused", stop: true, handler: func(http.ResponseWriter, *http.Request) {}},
		{name: "server error", handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			if tc.stop {
				srv.Close()
			}

			h := NewHIBP(WithHIBPBaseURL(srv.URL+"/range/"), WithHIBPTimeout(2*time.Second), WithHIBPFailClosed())
			err := h.Check(context.Background(), hibpTestPassword)
			if err == nil {
				t.Fatal("Check = nil, want an error (fail closed)")
			}
			if errors.Is(err, ErrCompromised) {
				t.Fatalf("Check = %v, but an unreachable service is not evidence that the password is compromised", err)
			}
		})
	}
}

// TestHIBPFailClosedStillRejectsACompromisedPassword makes sure the
// fail-closed switch changes only the unavailable case.
func TestHIBPFailClosedStillRejectsACompromisedPassword(t *testing.T) {
	_, _, suffix := hibpHash(hibpTestPassword)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, suffix+":1\r\n")
	}))
	defer srv.Close()

	h := NewHIBP(WithHIBPBaseURL(srv.URL+"/range/"), WithHIBPFailClosed())
	if err := h.Check(context.Background(), hibpTestPassword); !errors.Is(err, ErrCompromised) {
		t.Fatalf("Check = %v, want ErrCompromised", err)
	}
}

func TestHIBPHonorsTheContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "")
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	h := NewHIBP(WithHIBPBaseURL(srv.URL+"/range/"), WithHIBPFailClosed())
	if err := h.Check(ctx, hibpTestPassword); err == nil {
		t.Fatal("Check with a cancelled context = nil, want an error")
	}
}

func TestHIBPToleratesMalformedRows(t *testing.T) {
	_, _, suffix := hibpHash(hibpTestPassword)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, fmt.Sprintf("\r\ngarbage\r\n:::\r\nAAAA:notanumber\r\n%s:5\r\n\r\n", suffix))
	}))
	defer srv.Close()

	h := NewHIBP(WithHIBPBaseURL(srv.URL + "/range/"))
	if err := h.Check(context.Background(), hibpTestPassword); !errors.Is(err, ErrCompromised) {
		t.Fatalf("Check = %v, want ErrCompromised — a real hit after malformed rows must still be seen", err)
	}
}

// TestHIBPMalformedCountOnTheMatchingRowFailsOpen pins the case that
// TestHIBPToleratesMalformedRows does not cover: the garbage is on the row
// that actually matches our suffix, not on an unrelated one. lookup cannot
// parse "notanumber" as a count and surfaces that as an error (see the doc
// comment at the parse site in lookup) rather than silently continuing past
// it — but under the default fail-open policy, Check reads any lookup error
// as "no verdict" and accepts the password anyway, the same user-visible
// outcome as if this row had never matched at all. A real breach hit is
// silently missed here, which is why this needs a comment at the parse site
// (see lookup) and a test that would fail if a mutation ever turned
// "unparsable" into "compromised". Contrast with
// TestHIBPMalformedCountOnTheMatchingRowUnderFailClosed, where the very same
// response is rejected instead.
func TestHIBPMalformedCountOnTheMatchingRowFailsOpen(t *testing.T) {
	_, _, suffix := hibpHash(hibpTestPassword)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, suffix+":notanumber\r\n")
	}))
	defer srv.Close()

	h := NewHIBP(WithHIBPBaseURL(srv.URL + "/range/"))
	if err := h.Check(context.Background(), hibpTestPassword); err != nil {
		t.Fatalf("Check = %v, want nil — a matching row this client cannot parse is not a verdict, so the default fail-open policy applies", err)
	}
}

// TestHIBPMalformedCountOnTheMatchingRowUnderFailClosed pins the same
// response as above with WithHIBPFailClosed set. Fail-closed promises "no
// password without a completed check", and a row that matches our suffix but
// whose count cannot be parsed means the check did not complete — it is not
// a clean "not found" the way a malformed row for some *other* suffix is.
// So lookup surfaces this as an error (see the doc comment at the parse
// site), and fail-closed's existing error branch in Check rejects the
// password through the same seam it uses for a transport failure. This was
// flipped deliberately from the previously pinned fail-open-shaped behavior;
// see the commit that changed this test.
func TestHIBPMalformedCountOnTheMatchingRowUnderFailClosed(t *testing.T) {
	_, _, suffix := hibpHash(hibpTestPassword)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, suffix+":notanumber\r\n")
	}))
	defer srv.Close()

	h := NewHIBP(WithHIBPBaseURL(srv.URL+"/range/"), WithHIBPFailClosed())
	err := h.Check(context.Background(), hibpTestPassword)
	if err == nil {
		t.Fatal("Check = nil, want an error — fail-closed must reject a password whose check did not complete, and a matching row with an unparsable count is exactly that")
	}
	if errors.Is(err, ErrCompromised) {
		t.Fatalf("Check = %v, but a malformed row is not evidence the password is compromised, only that the check was incomplete", err)
	}
}

func TestHIBPAcceptsABaseURLWithoutATrailingSlash(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = io.WriteString(w, "")
	}))
	defer srv.Close()

	_, prefix, _ := hibpHash(hibpTestPassword)
	h := NewHIBP(WithHIBPBaseURL(srv.URL + "/range"))
	if err := h.Check(context.Background(), hibpTestPassword); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if want := "/range/" + prefix; path != want {
		t.Fatalf("request path = %q, want %q", path, want)
	}
}

func TestDefaultHIBPBaseURLIsTheRangeAPI(t *testing.T) {
	if !strings.HasPrefix(DefaultHIBPBaseURL, "https://") {
		t.Fatalf("DefaultHIBPBaseURL = %q, want an https URL — the prefix is not secret, but the response must not be tamperable", DefaultHIBPBaseURL)
	}
}
