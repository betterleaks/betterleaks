// Package scan discovers secrets with local regexes, decoding, and Expr filters.
// A Scanner performs no provider requests. Sources own input acquisition and may
// independently use the network, for example when scanning a remote repository.
//
// Load rules with config.Default or config.LoadFile, then call New. Rules and
// options are snapshotted and finding filters compile during construction.
// Regexes compile lazily unless WithPrecompile is supplied. Scanners are silent
// unless WithLogger is supplied.
// WithRegexEngine selects an engine for this scanner; the default is Go's
// standard library. The optional regexp/re2 package is imported only by callers
// that select it. An engine is retained rather than copied and must be safe for
// concurrent use.
//
// Use Scanner.Scan for callbacks and per-call statistics, Scanner.Run for an
// iterator of findings and recoverable source errors, or Scanner.ScanString for
// small inputs. Calls may run concurrently with independent sources and share
// the detection worker limit set by WithWorkers. Source and provider concurrency
// are configured independently.
//
// Findings carry detection confidence, captures, complete component combinations,
// and optional Match.Context requested with WithMatchContext. Analysis remains
// empty; filters extract other context directly from their source fragment. Use
// analyze.Analyzer to resolve credential state and permissions, or pipeline to
// compose both engines with independent workers and bounded queues.
package scan
