package totp

import (
	"strings"
	"testing"
	"time"
)

// FuzzGenerateCode exercises generateCode's base32 secret decoder — a
// hand-rolled parser with no fuzzing before this task. It must never panic
// on arbitrary secrets or times, a pre-1970 time must be rejected (the
// counterAt epoch guard added at T001), and whenever it succeeds the code
// returned must be exactly Digits ASCII digits.
func FuzzGenerateCode(f *testing.F) {
	seeds := []struct {
		secret  string
		unixSec int64
		digits  int
	}{
		{"JBSWY3DPEHPK3PXP", 1700000000, 6},
		{"", 1700000000, 6},
		{"not-base32!!", 1700000000, 8},
		{"AAAAAAAAAAAAAAAA", -1, 6},           // pre-epoch: the T001 counterAt guard
		{"AAAAAAAAAAAAAAAA", -62135596800, 6}, // year 1, well before the epoch
		{"AAAAAAAAAAAAAAAA", 0, 6},            // epoch boundary
		{"AAAAAAAAAAAAAAAA", 1 << 40, 8},      // far future
		{strings.Repeat("A", 1000), 1700000000, 7},
		{"aaaaaaaaaaaaaaaa", 1700000000, 6}, // lowercase; generateCode upper-cases
		{"AB=CD=", 1700000000, 6},           // padding char mid-string, invalid for NoPadding
		// RFC 6238 Appendix B vector whose 8-digit code has a leading zero
		// ("07081804"): pins that the digit count comes from the format
		// width, not the numeric value's natural length.
		{"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1111111109, 8},
	}
	for _, s := range seeds {
		f.Add(s.secret, s.unixSec, s.digits)
	}

	f.Fuzz(func(t *testing.T, secret string, unixSec int64, digitsRaw int) {
		// Clamp to the 6-8 range NewService enforces; generateCode itself
		// trusts its caller on this, so an out-of-range value would fail
		// the length property below for a reason unrelated to the parser
		// actually under test (the base32 decode).
		digits := 6 + int(uint32(digitsRaw)%3)
		cfg := Config{Algorithm: AlgorithmSHA1, Digits: digits, Period: 30}
		tm := time.Unix(unixSec, 0)

		code, err := generateCode(secret, tm, cfg)

		if unixSec < 0 {
			if err == nil {
				t.Fatalf("generateCode(%q, unix=%d, digits=%d) = %q, want an error: counterAt must reject pre-epoch times", secret, unixSec, digits, code)
			}
			return
		}

		if err != nil {
			return // a malformed secret is a valid rejection regardless of time
		}

		if len(code) != digits {
			t.Fatalf("generateCode(%q, unix=%d, digits=%d) = %q, want exactly %d chars", secret, unixSec, digits, code, digits)
		}
		for _, r := range code {
			if r < '0' || r > '9' {
				t.Fatalf("generateCode(%q, unix=%d, digits=%d) = %q, contains non-digit %q", secret, unixSec, digits, code, r)
			}
		}
	})
}
