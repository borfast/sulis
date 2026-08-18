package recovery

import (
	"strings"
	"testing"
)

// FuzzRecoveryCanonical exercises canonical, the hand-rolled normalizer that
// turns a user-typed recovery code into the form that gets hashed and
// compared against stored codes. It must never panic, and normalizing an
// already-canonical string must be a no-op — the same round-trip/idempotency
// guarantee the sibling fuzz targets pin for normalizeEmail and decodeHash.
func FuzzRecoveryCanonical(f *testing.F) {
	seeds := []string{
		"",
		"abcd-efgh-ijkl-mnop",
		"ABCD-EFGH-IJKL-MNOP",
		"  abcd-efgh-ijkl-mnop  ",
		"----",
		"a b c d",
		"a-b c-d",
		"- - - -  ",
		strings.Repeat("x", 4096),
		"日本語コード-テスト",
		"\t\n abc \t\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		got := canonical(s) // must not panic

		got2 := canonical(got)
		if got2 != got {
			t.Fatalf("canonical not idempotent: canonical(%q) = %q, canonical(that) = %q", s, got, got2)
		}
	})
}
