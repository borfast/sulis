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

func decodeHash(encoded string) (params Argon2Params, salt, hash []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return params, nil, nil, fmt.Errorf("sulis: invalid hash format")
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
	params.SaltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return params, nil, nil, fmt.Errorf("sulis: decoding hash: %w", err)
	}
	params.KeyLength = uint32(len(hash))

	return params, salt, hash, nil
}
