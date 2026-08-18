package passwordcheck

import (
	"context"
	_ "embed"
	"strings"
	"sync"
)

// commonPasswordsFile is a corpus of the ten thousand most common passwords,
// embedded so a deployment gets a meaningful check with no network access,
// no third party, and nothing to configure.
//
// # Provenance
//
// Retrieved 2026-08-18, verbatim and unmodified, from:
//
//	https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt
//
// SecLists (github.com/danielmiessler/SecLists) is MIT licensed. The file was
// last changed upstream in commit a3416ba7062a1bc2ec6b0fe76eac7ee16c80521b
// (2020-05-27). The copy in this repository is byte-for-byte identical to
// what that URL served, so it can be re-verified without trusting this
// commit:
//
//	sha256  4adb3f0afb4a10cf19ebe48d8c69a46f934bbc8d77c694c210564f9583e7f4ba
//	lines   10000
//	bytes   73017
//
// Format: one password per line, LF-terminated, already entirely lowercase.
// It is a corpus of real breached passwords, so it contains slurs and
// obscenities; that is what the data is, and filtering it would only make the
// blocklist weaker at the words attackers actually try first.
//
// Refreshing it means re-running the fetch and updating the three figures
// above. Nothing else in this package depends on the file's contents beyond
// "one candidate per line".
//
//go:embed common-passwords.txt
var commonPasswordsFile string

// commonPasswords parses the embedded corpus into a set, once per process and
// only if something actually asks. Deferring it matters: sulis's default
// configuration constructs a Blocklist in every New, and most processes
// create theirs long before the first password is ever set — some never set
// one at all.
var commonPasswords = sync.OnceValue(func() map[string]struct{} {
	set := make(map[string]struct{}, 10240)
	for line := range strings.Lines(commonPasswordsFile) {
		entry := strings.ToLower(strings.TrimRight(line, "\r\n"))
		if entry == "" {
			continue
		}
		set[entry] = struct{}{}
	}
	return set
})

// Blocklist rejects passwords that appear in an embedded corpus of the ten
// thousand most common passwords, plus any extra entries supplied to
// [NewBlocklist].
//
// Comparison folds case: the corpus is lowercase, and so is the candidate
// before lookup. An attacker's dictionary is case-folded too, so matching
// only the exact lowercase spelling would be bypassed by pressing shift once.
// The cost is that Blocklist rejects slightly more than the literal corpus —
// "PASSWORD" is refused although only "password" is listed, which is the
// right trade.
//
// Nothing else is stripped or folded. A decorated variant such as
// "password!" is not in the corpus and is not rejected here; catching those
// is what [NewHIBP] is for, since the breach corpus behind it already
// contains the decorated variants people actually chose.
//
// # What the default minimum length leaves it to do
//
// Common passwords are short. At sulis's default MinPasswordLength of 12,
// only ten of the corpus's ten thousand entries are even reachable — the
// length gate rejects the rest first, and rejects them for a better reason.
// The blocklist earns its place in two situations: a deployment that lowers
// the minimum via sulis.WithPasswordLengthLimits, and site-specific words
// passed to [NewBlocklist] (a company name, a product, a stadium) which are
// exactly the twelve-plus-character passwords a targeted attacker tries
// first. For breadth beyond that, add [NewHIBP].
//
// A Blocklist is safe for concurrent use.
type Blocklist struct {
	extra map[string]struct{}
}

// NewBlocklist returns a [Blocklist] over the embedded common-password corpus,
// plus any extra values given. Extras are compared case-insensitively, like
// corpus entries, and are the place to put words specific to your
// deployment — the organisation's name, its products, its city — which no
// general corpus can know about but a targeted attacker will try early.
//
// The returned value is cheap: the corpus is parsed lazily, at most once per
// process, and shared by every Blocklist.
func NewBlocklist(extra ...string) *Blocklist {
	b := &Blocklist{}
	if len(extra) > 0 {
		b.extra = make(map[string]struct{}, len(extra))
		for _, e := range extra {
			b.extra[strings.ToLower(e)] = struct{}{}
		}
	}
	return b
}

// Check reports [ErrCompromised] if password appears in the embedded corpus
// or among the extras, and nil otherwise. It never fails for any other
// reason: there is nothing to reach and nothing to time out, which is why
// this is the default checker.
//
// The empty string is always accepted. An empty password is the length
// policy's rejection to make, and answering "appears in a breach corpus"
// would be a lie about data this package does not have.
func (b *Blocklist) Check(_ context.Context, password string) error {
	if password == "" {
		return nil
	}
	folded := strings.ToLower(password)
	if _, found := b.extra[folded]; found {
		return ErrCompromised
	}
	if _, found := commonPasswords()[folded]; found {
		return ErrCompromised
	}
	return nil
}
