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
// # Concurrency
//
// Every method is safe for concurrent use. Values returned to callers are
// always copies, and values handed in are always copied before being stored,
// so a caller mutating a struct it passed in or got back can never reach
// inside the store.
package memstore
