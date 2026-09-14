// Package scan discovers secrets with local regexes, decoding, and Expr filters.
// A Scanner performs no provider requests. Sources own input acquisition and may
// independently use the network, for example when scanning a remote repository.
//
// Load rules with config.Default or config.LoadFile, then call New. Rules and
// options are snapshotted; regexes and filters compile lazily unless
// WithPrecompile is supplied. Scanners are silent unless WithLogger is supplied.
//
// Use Scanner.Scan for callbacks and per-call statistics, Scanner.Run for an
// iterator of findings and recoverable source errors, or Scanner.ScanString for
// small inputs. Calls may run concurrently with independent sources.
//
// Findings carry detection confidence, captures, complete component combinations,
// and private expression context. Validation and Analysis remain empty. Use
// analyze.Analyzer to resolve credential state and permissions, or pipeline to
// compose both engines with independent workers and bounded queues.
package scan
