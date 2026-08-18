package sulis

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// hashPassword hashes a password using argon2id with the given parameters.
// Returns a PHC-format string: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
func hashPassword(password string, params Argon2Params) (string, error) {
	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("sulis: generating salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
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
func verifyPassword(password, encoded string) (bool, error) {
	params, salt, hash, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}

	otherHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
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
