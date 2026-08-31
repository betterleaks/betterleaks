// Package detect provides the reusable secret-detection engine.
//
// Construct a Detector with NewDetector and functional options, then call Scan
// for error handling and per-call statistics. Run remains available for callers
// that prefer an iterator over individual findings and recoverable source errors.
package detect
