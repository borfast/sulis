package sulis

import "time"

// Argon2Params holds the parameters for argon2id password hashing.
type Argon2Params struct {
	Memory      uint32 // memory in KiB (default: 64 * 1024)
	Iterations  uint32 // time parameter (default: 3)
	Parallelism uint8  // threads (default: 2)
	SaltLength  uint32 // bytes (default: 16)
	KeyLength   uint32 // bytes (default: 32)
}

// Config holds the configuration for a Sulis instance.
type Config struct {
	SessionDuration   time.Duration // how long sessions are valid (default: 24h)
	TokenDuration     time.Duration // how long reset/magic link tokens are valid (default: 1h)
	SessionTokenBytes int           // length of random session tokens in bytes (default: 32)
	ResetTokenBytes   int           // length of random reset/magic link tokens in bytes (default: 32)
	Argon2            Argon2Params
}

// Option is a functional option for configuring Sulis.
type Option func(*Config)

func defaultConfig() Config {
	return Config{
		SessionDuration:   24 * time.Hour,
		TokenDuration:     1 * time.Hour,
		SessionTokenBytes: 32,
		ResetTokenBytes:   32,
		Argon2: Argon2Params{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 2,
			SaltLength:  16,
			KeyLength:   32,
		},
	}
}

// WithSessionDuration sets how long sessions remain valid.
func WithSessionDuration(d time.Duration) Option {
	return func(c *Config) { c.SessionDuration = d }
}

// WithTokenDuration sets how long password reset and magic link tokens remain valid.
func WithTokenDuration(d time.Duration) Option {
	return func(c *Config) { c.TokenDuration = d }
}

// WithArgon2Params sets custom argon2id parameters for password hashing.
func WithArgon2Params(p Argon2Params) Option {
	return func(c *Config) { c.Argon2 = p }
}
