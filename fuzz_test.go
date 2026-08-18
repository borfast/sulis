package sulis

import (
	"strings"
	"testing"
)

// fuzzArgon2Params are the weakest Argon2Params decodeHash's bounds check
// (password.go) and hashPassword accept as valid: Memory at the
// 8*Parallelism floor, Iterations and Parallelism at their 1 minimum, and
// salt/key at the shortest lengths decodeHash will still decode (8 and 16
// bytes). FuzzDecodeHash's round-trip property only needs a hash that
// decodeHash accepts, not one shaped like a production hash, so hashing at
// these floors instead of testArgon2Params (chosen to still resemble a real
// deployment) turns the one Argon2 hash paid per exec from the dominant cost
// into a negligible one, without weakening the property under test.
var fuzzArgon2Params = Argon2Params{
	Memory:      8,
	Iterations:  1,
	Parallelism: 1,
	SaltLength:  8,
	KeyLength:   16,
}

// FuzzDecodeHash exercises decodeHash, the hand-rolled PHC-format parser
// behind password verification. It must never panic on arbitrary input, and
// every hash hashPassword produces must decode back out successfully — a
// hand-rolled parser and its own writer disagreeing would mean legitimate
// passwords stop verifying.
func FuzzDecodeHash(f *testing.F) {
	seeds := []string{
		"",
		"not a hash at all",
		"$argon2id$v=19$m=8192,t=1,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2i$v=19$m=8192,t=1,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",         // wrong algorithm
		"$argon2id$v=1$m=8192,t=1,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",         // wrong version
		"$argon2id$v=19$m=0,t=0,p=0$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",           // zero params
		"$argon2id$v=19$m=99999999999,t=1,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", // huge memory
		"$argon2id$v=19$m=8192,t=1,p=1$$",                                         // empty salt/hash
		"$$$$$$$$",
		"argon2id$v=19$m=8192,t=1,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", // missing leading $
		"correct horse battery staple",
		"p@ssw0rd!! \U0001F525",
		strings.Repeat("a", 4096),
		strings.Repeat("$", 4096),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		// Property 1: decodeHash must never panic on arbitrary input,
		// well-formed or not.
		_, _, _, _ = decodeHash(s)

		// Property 2 (round trip): whatever hashPassword produces must
		// always decode back out, with the same params/lengths it was
		// hashed with. Bound the password length fed to Argon2 so a huge
		// fuzz-generated string doesn't make every iteration slow; the
		// no-panic property above already covers the full, unbounded
		// string against decodeHash directly.
		password := s
		if len(password) > 256 {
			password = password[:256]
		}
		hash, err := hashPassword(password, fuzzArgon2Params, nil)
		if err != nil {
			return // crypto/rand failure path; nothing to check here
		}
		params, salt, key, err := decodeHash(hash)
		if err != nil {
			t.Fatalf("decodeHash(hashPassword(%q)) failed: %v", password, err)
		}
		if params != fuzzArgon2Params {
			t.Fatalf("decodeHash(hashPassword(%q)) params = %+v, want %+v", password, params, fuzzArgon2Params)
		}
		if len(salt) != int(fuzzArgon2Params.SaltLength) {
			t.Fatalf("decodeHash(hashPassword(%q)) salt length = %d, want %d", password, len(salt), fuzzArgon2Params.SaltLength)
		}
		if len(key) != int(fuzzArgon2Params.KeyLength) {
			t.Fatalf("decodeHash(hashPassword(%q)) key length = %d, want %d", password, len(key), fuzzArgon2Params.KeyLength)
		}
	})
}

// FuzzNormalizeEmail exercises normalizeEmail, the RFC 5322 address parser
// behind every email-taking entry point. It must never panic, any address it
// accepts must already be in the canonical form it promises (lowercase,
// trimmed, <=254 bytes), and normalizing an already-normalized address must
// be a no-op.
func FuzzNormalizeEmail(f *testing.F) {
	seeds := []string{
		"alice@example.com",
		"  Alice@Example.COM  ",
		"",
		"   ",
		"not-an-email",
		"a@b",
		"Name <a@b.com>",
		"\"quoted local\"@example.com",
		strings.Repeat("a", 260) + "@example.com",
		"a@" + strings.Repeat("b", 260) + ".com",
		"üser@exämple.com",
		"a@b.com\x00",
		"a@b@c.com",
		"\t\nalice@example.com\t\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		got, err := normalizeEmail(s)
		if err != nil {
			return // rejection is always a valid outcome
		}

		if got != strings.ToLower(got) {
			t.Fatalf("normalizeEmail(%q) = %q, not lowercase", s, got)
		}
		if got != strings.TrimSpace(got) {
			t.Fatalf("normalizeEmail(%q) = %q, has untrimmed whitespace", s, got)
		}
		if len(got) > 254 {
			t.Fatalf("normalizeEmail(%q) = %q, exceeds 254 bytes (got %d)", s, got, len(got))
		}

		got2, err2 := normalizeEmail(got)
		if err2 != nil {
			t.Fatalf("normalizeEmail(normalizeEmail(%q)) = %q, error %v; want it to accept its own output", s, got, err2)
		}
		if got2 != got {
			t.Fatalf("normalizeEmail not idempotent: normalizeEmail(%q) = %q, normalizeEmail(that) = %q", s, got, got2)
		}
	})
}
