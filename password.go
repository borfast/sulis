package sulis

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// normalizePassword returns the Unicode NFKC form of password. It is the
// single definition of "the same password" in this library: every path that
// hashes, verifies, length-checks, or screens a password works on this form
// and never on the caller's raw bytes.
//
// Without it, whether a password verifies depends on which keyboard produced
// it. "café" typed on macOS arrives as "e" plus a combining acute accent
// (NFD); the same password typed on Windows or Linux usually arrives as the
// single precomposed rune U+00E9. They are different byte strings, so they
// hash differently, and a user who registers on one device and logs in from
// another is told their password is wrong with no way to find out why.
//
// NFKC rather than NFC because the compatibility mappings matter here too:
// the "fi" ligature U+FB01, fullwidth digits, and the like are single
// keystrokes on some input methods and plain ASCII on others. NFKC folds
// those together as well, at the price of treating a handful of visually
// distinct characters as equal — a rounding error against passwords that
// cannot be typed twice.
//
// NFKC is idempotent, which everything downstream relies on: hashPassword
// normalizes even though checkPasswordPolicy already did, so no future path
// can reach the hasher with an unnormalized password by forgetting a step.
//
// Invalid UTF-8 passes through unchanged rather than being replaced or
// rejected: a password is a byte string the user must be able to reproduce,
// not text this library is entitled to correct.
func normalizePassword(password string) string {
	return norm.NFKC.String(password)
}

// hashPassword hashes a password using argon2id with the given parameters.
// Returns a PHC-format string: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
//
// The password is normalized (see normalizePassword) first, so every hash
// this library writes is a hash of the NFKC form regardless of which caller
// produced it or what they had already done to the string. This is the choke
// point that makes "normalize on every path that sets a password" a property
// of the code rather than a rule to remember.
func hashPassword(password string, params Argon2Params) (string, error) {
	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("sulis: generating salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(normalizePassword(password)),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		params.Memory,
		params.Iterations,
		params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// verifyPassword checks a password against an argon2id PHC-format hash.
//
// The comparison is made against the NFKC form of password (see
// normalizePassword), matching what hashPassword writes. If that does not
// match AND the normalized form differs from the raw bytes the caller passed,
// the raw form is tried as well, and a match that way is reported by the
// second return value.
//
// That fallback is the migration path for hashes written before
// normalization existed: they were derived from raw bytes, so a user whose
// password is not already NFKC-normal would otherwise be locked out of their
// own account by an upgrade, with an ordinary ErrInvalidCredentials and no
// route back short of a password reset. A caller that sees legacy true has
// just been handed the plaintext and a verified match, which is exactly the
// moment to re-hash the stored value into the normalized form — see
// (*Sulis).rehashPassword, the same machinery T504 built for raising Argon2
// parameters. After one successful login the account is migrated and the
// fallback never fires for it again.
//
// The fallback widens nothing. It compares the caller's exact bytes against
// the stored hash, so the only password it can ever accept is the one that
// hash was already derived from; no string that failed before this change
// succeeds after it.
//
// Cost: for an already-normal password — every ASCII password, so very nearly
// all of them — the two forms are identical and there is no second Argon2
// comparison to pay for. When they do differ, a wrong password costs two
// comparisons instead of one. That is not an oracle: the attacker chooses the
// form they send, so the doubling is a property of their own input and says
// nothing about the account. It also holds uniformly, because VerifyPassword's
// unknown-user and passwordless branches run this same function against the
// dummy hash and so pay the same doubled cost.
func verifyPassword(password, encoded string) (ok, legacy bool, err error) {
	params, salt, hash, err := decodeHash(encoded)
	if err != nil {
		return false, false, err
	}

	compare := func(candidate string) bool {
		otherHash := argon2.IDKey(
			[]byte(candidate),
			salt,
			params.Iterations,
			params.Memory,
			params.Parallelism,
			params.KeyLength,
		)
		return subtle.ConstantTimeCompare(hash, otherHash) == 1
	}

	normalized := normalizePassword(password)
	if compare(normalized) {
		return true, false, nil
	}
	if normalized == password {
		return false, false, nil
	}
	if compare(password) {
		return true, true, nil
	}
	return false, false, nil
}

// needsRehash reports whether encoded — a stored password hash that has
// already been successfully verified against — was produced with weaker
// Argon2 parameters than want and should be regenerated from the plaintext
// now that it's available. Only the cost dimensions matter: memory,
// iterations, and parallelism. SaltLength/KeyLength are fixed by the hash
// that already exists and are not compared here; a hash weaker in any of
// the three cost dimensions is considered to need an upgrade, and a hash
// that's equal or stronger in all three does not — there is never a reason
// to downgrade a hash the operator hasn't asked to weaken.
//
// A hash that fails to decode is treated as NOT needing a rehash, not as
// needing one. verifyPassword already rejects a malformed hash before this
// is ever consulted (VerifyPassword only reaches needsRehash on a
// successful verification), so this can only be reached with a hash that
// decoded fine moments ago; a decode failure here is not a plausible path
// to a bypass, just a safe default in case it's ever called differently.
func needsRehash(encoded string, want Argon2Params) bool {
	got, _, _, err := decodeHash(encoded)
	if err != nil {
		return false
	}
	return got.Memory < want.Memory ||
		got.Iterations < want.Iterations ||
		got.Parallelism < want.Parallelism
}

func decodeHash(encoded string) (params Argon2Params, salt, hash []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return params, nil, nil, fmt.Errorf("sulis: invalid hash format")
	}

	if parts[1] != "argon2id" {
		return params, nil, nil, fmt.Errorf("sulis: unsupported algorithm %q", parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return params, nil, nil, fmt.Errorf("sulis: parsing version: %w", err)
	}
	if version != argon2.Version {
		return params, nil, nil, fmt.Errorf("sulis: unsupported argon2 version %d", version)
	}

	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Iterations, &params.Parallelism); err != nil {
		return params, nil, nil, fmt.Errorf("sulis: parsing params: %w", err)
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return params, nil, nil, fmt.Errorf("sulis: decoding salt: %w", err)
	}

	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return params, nil, nil, fmt.Errorf("sulis: decoding hash: %w", err)
	}

	switch {
	case params.Parallelism == 0,
		params.Iterations == 0 || params.Iterations > 1024,
		params.Memory < 8*uint32(params.Parallelism) || params.Memory > 1<<22, // 4 GiB cap
		len(salt) < 8 || len(salt) > 64,
		len(hash) < 16 || len(hash) > 128:
		return params, nil, nil, fmt.Errorf("sulis: hash parameters out of bounds")
	}

	// Widened only after the bounds check above, so both lengths are known to
	// fit (salt <= 64, hash <= 128) and the conversion cannot truncate.
	params.SaltLength = uint32(len(salt)) // #nosec G115 -- bounded to 64 by the check above
	params.KeyLength = uint32(len(hash))  // #nosec G115 -- bounded to 128 by the check above

	return params, salt, hash, nil
}
