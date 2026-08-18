// Package memstore is the reference in-memory implementation of every store
// interface sulis defines.
//
// It exists to be read. Each store interface in this module documents
// atomicity, scoping, and monotonicity requirements that a real
// implementation has to satisfy with transactions, conditional statements, or
// locks; the types here satisfy them with a single mutex each, held across
// the whole check-and-mutate, which makes the required boundary visible in a
// dozen lines instead of a page of SQL. When adapting one of these to a
// database, the mutex is what your transaction or your single conditional
// statement has to replace — not something you can drop.
//
// Every type here passes the whole storetest conformance suite, which is how
// that claim is kept honest rather than asserted; see memstore_test.go.
//
// # Not for production
//
// These stores keep everything in process memory. Nothing survives a
// restart, nothing is shared between processes, and nothing is bounded:
// CleanExpired, DeleteExpiredTokens, and the delete methods are the only
// things that ever release memory, so a long-lived process that never calls
// them grows without limit. Use them for tests, examples, and local
// development.
//
// # Concurrency and isolation
//
// Every method is safe for concurrent use. Values returned to callers are
// always copies, and values handed in are always copied before being stored,
// so a caller mutating a struct it passed in or got back can never reach
// inside the store.
//
// "Copy" here means deep enough that nothing mutable is shared: the maps
// (sulis.User.Metadata, sulis.Session.Metadata), the slices
// (passkey.Credential.CredentialID, PublicKey, AAGUID, Transports, and
// challenge session data), and the pointers (sulis.User.EmailVerifiedAt,
// passkey.Credential.LastUsedAt) are all cloned on the way in and on the way
// out. A plain struct copy would not be: it copies a map header, not the map,
// which would leave a caller able to rewrite a persisted row without going
// through UpdateUser — precisely what sulis.User.Version exists to prevent.
// The one documented limit is that maps are cloned one level deep, so a
// caller that stores a map or a slice as a Metadata *value* still shares that
// inner value with the store.
//
// This is not a memstore quirk. storetest enforces the same property on every
// conforming implementation.
package memstore
