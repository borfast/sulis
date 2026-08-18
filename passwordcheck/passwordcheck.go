// Package passwordcheck screens passwords against known-compromised values.
//
// NIST SP 800-63B asks that a password chosen by a user be compared against
// a list of values known to be commonly used, expected, or compromised, and
// rejected if it appears there. Length alone does not do this: "iloveyou1234"
// is twelve characters and has been breached millions of times.
//
// Two checkers ship here:
//
//   - [NewBlocklist] compares against a corpus of common passwords embedded
//     in the binary. No network, no third party, no failure mode. This is the
//     default in sulis, and it is what a deployment gets without asking.
//   - [NewHIBP] queries the Have I Been Pwned range API, which covers orders
//     of magnitude more passwords than any list worth embedding. It is
//     opt-in because it makes password *changes* depend on a third party
//     being reachable — see the fail-open/fail-closed discussion on [NewHIBP].
//
// Use [All] to run both:
//
//	sulis.WithPasswordChecker(passwordcheck.All(
//		passwordcheck.NewBlocklist(),
//		passwordcheck.NewHIBP(),
//	))
//
// # Relationship to sulis
//
// This package deliberately does not import sulis: sulis's default
// configuration constructs a [Blocklist], so an import in this direction
// would be a cycle. [Checker] here and sulis.PasswordChecker there are the
// same method set, so any checker written against either interface satisfies
// both, and [ErrCompromised] is the very same error value sulis exports as
// sulis.ErrPasswordCompromised — errors.Is works against either name.
//
// # Normalization
//
// sulis applies Unicode NFKC normalization to a password before it reaches a
// checker, so what arrives at [Checker.Check] is exactly the string that will
// be hashed and stored. A checker used standalone is handed whatever its
// caller passes; if that caller also hashes the raw form, normalize on both
// sides or the comparison and the hash disagree about what the password is.
package passwordcheck

import (
	"context"
	"errors"
)

// ErrCompromised is returned by a [Checker] that recognises a password as
// commonly used, expected, or previously breached. sulis re-exports this
// exact value as sulis.ErrPasswordCompromised, so errors.Is matches it under
// either name.
//
// It says nothing about the account: a password can be rejected here on the
// first registration attempt, before any account exists. Callers should
// surface it to the user as "choose a different password", never as a
// credential or account failure.
var ErrCompromised = errors.New("sulis: password appears in a breach corpus")

// Checker screens a candidate password.
//
// Check returns nil if the password is acceptable, [ErrCompromised] (or an
// error wrapping it) if the password is known-compromised, and any other
// error if it could not reach a verdict. Callers must treat those last two
// cases differently: an unreachable breach corpus is an operational failure,
// not evidence about the password, and reporting it as one teaches users to
// distrust the message.
//
// Implementations must be safe for concurrent use and must respect ctx.
//
// This is the same method set as sulis.PasswordChecker; either interface
// accepts a value implementing the other.
type Checker interface {
	Check(ctx context.Context, password string) error
}

// CheckerFunc adapts an ordinary function to [Checker].
type CheckerFunc func(ctx context.Context, password string) error

// Check calls f.
func (f CheckerFunc) Check(ctx context.Context, password string) error {
	return f(ctx, password)
}

// All returns a [Checker] that runs each of checkers in order and returns the
// first non-nil error, or nil if every one of them accepts the password.
//
// Order matters: put the cheap local checks first so an obviously bad
// password is rejected without a network round trip. All() with no arguments
// accepts every password, which is a usable "checking is configured, but this
// deployment has nothing to check" value.
func All(checkers ...Checker) Checker {
	all := make([]Checker, len(checkers))
	copy(all, checkers)
	return CheckerFunc(func(ctx context.Context, password string) error {
		for _, c := range all {
			if err := c.Check(ctx, password); err != nil {
				return err
			}
		}
		return nil
	})
}
