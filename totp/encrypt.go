package totp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// Encryptor encrypts and decrypts the string Credential.Secret carries
// before Service ever hands it to a Store, and decrypts it immediately
// after reading one back — see WithEncryptor. A Store implementation never
// sees a usable TOTP secret, and its author never has to think about this
// protection at all: the protection lives entirely inside this package.
//
// Both methods operate on and return plain strings, exactly the type
// Credential.Secret already is, so a configured Encryptor's output
// round-trips through Store completely unchanged — no store contract,
// schema, or column type needs to know encryption exists.
type Encryptor interface {
	// Encrypt returns an opaque string encoding plaintext such that only
	// Decrypt (with the right key) can recover it. Two calls with the same
	// plaintext MUST produce different ciphertexts — via a random nonce,
	// for instance — so equal secrets are never visible as equal strings to
	// whatever ends up storing the result.
	Encrypt(plaintext string) (string, error)

	// Decrypt reverses Encrypt. It MUST fail closed: a wrong key, corrupted
	// or truncated ciphertext, or any other anomaly must return a non-nil
	// error, never a plausible-looking but wrong plaintext. A caller that
	// forgets to check the error must never silently receive garbage in
	// place of a secret.
	Decrypt(ciphertext string) (string, error)
}

const (
	aesKeySize   = 32 // AES-256
	aesKeyIDSize = 8  // bytes of key fingerprint prefixed onto every ciphertext
)

// AESEncryptor implements Encryptor with AES-256-GCM: a random 96-bit nonce
// on every Encrypt call (crypto/rand — never reused, so encrypting the same
// secret twice yields two unrelated ciphertexts), and a per-key fingerprint
// prefixed onto the output so Decrypt can tell which of possibly several
// configured keys produced a given ciphertext, without any external key-ID
// bookkeeping.
type AESEncryptor struct {
	current   cipher.AEAD
	currentID []byte
	keys      map[string]cipher.AEAD // fingerprint (as a string) -> AEAD
}

var _ Encryptor = (*AESEncryptor)(nil)

// NewAESEncryptor builds an AES-256-GCM Encryptor. key must be exactly 32
// bytes (AES-256) and is the CURRENT key: every future Encrypt call uses
// it. rotated, if given, are additional keys Decrypt will also accept —
// typically previous values of key — so ciphertext written under them keeps
// decrypting after a rotation; every key in rotated must also be exactly 32
// bytes.
//
// Rotating a key means: construct a new AESEncryptor with the new key as
// key and the old key(s) as rotated, and swap it in via WithEncryptor.
// Already-stored ciphertext keeps decrypting (its embedded fingerprint
// still names the old key, which is still configured); every new Encrypt
// call moves to the new key. There is no in-place "re-encrypt everything"
// step — like Argon2's rehash-on-login (T504), a secret only actually moves
// onto the new key the next time Service writes it (Validate's counter
// bump, or a fresh Enroll/ReplaceEnrollment), not immediately on rotation.
//
// A key's fingerprint — the key-ID prefix embedded in its ciphertext — is
// derived from the key itself (HMAC-SHA256 keyed by the key, over a fixed
// label, truncated to 8 bytes), never assigned by the caller or inferred
// from argument position. That is deliberate: passing the same keys back in
// a different order, or promoting an old key to current, can never make an
// existing ciphertext's fingerprint resolve to the wrong key.
func NewAESEncryptor(key []byte, rotated ...[]byte) (*AESEncryptor, error) {
	all := make([][]byte, 0, 1+len(rotated))
	all = append(all, key)
	all = append(all, rotated...)

	enc := &AESEncryptor{keys: make(map[string]cipher.AEAD, len(all))}
	for i, k := range all {
		if len(k) != aesKeySize {
			return nil, fmt.Errorf("totp: encryption key must be %d bytes, got %d", aesKeySize, len(k))
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, fmt.Errorf("totp: constructing AES cipher: %w", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("totp: constructing GCM: %w", err)
		}

		id := keyFingerprint(k)
		enc.keys[string(id)] = gcm
		if i == 0 {
			enc.current, enc.currentID = gcm, id
		}
	}
	return enc, nil
}

// keyFingerprint derives an 8-byte identifier for key: HMAC-SHA256 keyed by
// key itself, over a fixed label, truncated. It need not be secret — it is
// a lookup index embedded in every ciphertext in the clear, exactly like a
// PHC hash's algorithm/params prefix (see password.go's decodeHash) — only
// distinct per key with overwhelming probability, which a keyed hash gives
// without requiring the caller to invent and track key IDs themselves.
func keyFingerprint(key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("sulis/totp/aes-key-id"))
	return mac.Sum(nil)[:aesKeyIDSize]
}

// errCiphertextTruncated and errUnknownKeyID name the two decrypt anomalies
// diagnosable before ever calling AEAD.Open; a wrong key or a tampered
// ciphertext instead fails inside Open itself, surfaced as its own
// (deliberately unwrapped-of-detail) error. All three outcomes are equally
// "fail closed": Decrypt never returns a nil error alongside anything other
// than the genuine plaintext.
var (
	errCiphertextTruncated = errors.New("totp: ciphertext truncated")
	errUnknownKeyID        = errors.New("totp: unknown encryption key id")
)

// Encrypt implements Encryptor.
func (e *AESEncryptor) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, e.current.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("totp: generating nonce: %w", err)
	}

	sealed := e.current.Seal(nil, nonce, []byte(plaintext), nil)

	raw := make([]byte, 0, len(e.currentID)+len(nonce)+len(sealed))
	raw = append(raw, e.currentID...)
	raw = append(raw, nonce...)
	raw = append(raw, sealed...)

	return base64.StdEncoding.EncodeToString(raw), nil
}

// Decrypt implements Encryptor.
func (e *AESEncryptor) Decrypt(ciphertext string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("totp: decoding ciphertext: %w", err)
	}

	if len(raw) < aesKeyIDSize {
		return "", errCiphertextTruncated
	}
	id, rest := raw[:aesKeyIDSize], raw[aesKeyIDSize:]

	gcm, ok := e.keys[string(id)]
	if !ok {
		return "", errUnknownKeyID
	}

	nonceSize := gcm.NonceSize()
	if len(rest) < nonceSize {
		return "", errCiphertextTruncated
	}
	nonce, sealed := rest[:nonceSize], rest[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", fmt.Errorf("totp: decrypting secret: %w", err)
	}
	return string(plaintext), nil
}
