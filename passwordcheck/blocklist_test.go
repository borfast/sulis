package passwordcheck

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestBlocklistRejectsACommonPassword(t *testing.T) {
	b := NewBlocklist()
	ctx := context.Background()

	for _, password := range []string{
		"password",     // rank 1 in the embedded corpus
		"123456",       // rank 2
		"unbelievable", // one of the few entries long enough to survive the 12-character default minimum
	} {
		err := b.Check(ctx, password)
		if !errors.Is(err, ErrCompromised) {
			t.Errorf("Check(%q) = %v, want ErrCompromised", password, err)
		}
	}
}

func TestBlocklistAcceptsAPasswordThatIsNotInTheCorpus(t *testing.T) {
	b := NewBlocklist()
	if err := b.Check(context.Background(), "correct-battery-staple"); err != nil {
		t.Fatalf("Check on a password absent from the corpus: %v", err)
	}
}

// TestBlocklistIsCaseInsensitive is the difference between a blocklist and a
// decoration: an attacker's dictionary is case-folded, so a list that only
// matches the exact lowercase spelling is bypassed by pressing shift once.
func TestBlocklistIsCaseInsensitive(t *testing.T) {
	b := NewBlocklist()
	ctx := context.Background()

	for _, password := range []string{"Unbelievable", "UNBELIEVABLE", "UnBeLiEvAbLe"} {
		if err := b.Check(ctx, password); !errors.Is(err, ErrCompromised) {
			t.Errorf("Check(%q) = %v, want ErrCompromised", password, err)
		}
	}
}

func TestBlocklistAcceptsExtraEntries(t *testing.T) {
	b := NewBlocklist("Acme-Corp-2026", "hunter2")
	ctx := context.Background()

	for _, password := range []string{"acme-corp-2026", "ACME-CORP-2026", "hunter2"} {
		if err := b.Check(ctx, password); !errors.Is(err, ErrCompromised) {
			t.Errorf("Check(%q) = %v, want ErrCompromised", password, err)
		}
	}
	if err := b.Check(ctx, "acme-corp-2027"); err != nil {
		t.Errorf("Check on a password not in the corpus or the extras: %v", err)
	}
}

// TestBlocklistCorpusIsIntact guards the embedded file itself: a truncated,
// unparsed, or accidentally-emptied corpus would make every Check above pass
// for the wrong reason, and a blocklist that accepts everything fails silently.
func TestBlocklistCorpusIsIntact(t *testing.T) {
	entries := commonPasswords()
	if len(entries) < 9000 {
		t.Fatalf("embedded corpus holds %d entries, want at least 9000 — the file looks truncated", len(entries))
	}
	for entry := range entries {
		if entry == "" {
			t.Fatal("the embedded corpus contains an empty entry; an empty password would be reported as compromised for the wrong reason")
		}
		if entry != strings.ToLower(entry) {
			t.Fatalf("corpus entry %q is not lowercased; lookups fold case, so a mixed-case entry is unreachable", entry)
		}
		if strings.ContainsAny(entry, "\r\n") {
			t.Fatalf("corpus entry %q carries a line terminator", entry)
		}
	}
}

func TestBlocklistAcceptsAnEmptyPassword(t *testing.T) {
	// Not the blocklist's job: an empty password is the length policy's
	// rejection to make, and reporting it as "appears in a breach corpus"
	// would be a lie.
	if err := NewBlocklist().Check(context.Background(), ""); err != nil {
		t.Fatalf("Check(\"\") = %v, want nil", err)
	}
}
