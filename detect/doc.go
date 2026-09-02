// Package detect provides the reusable secret-detection engine.
//
// Load Betterleaks' built-in rules with config.Default, or load an application-
// owned betterleaks.toml with config.LoadFile. Pass the resulting config.Config
// to [NewDetector].
//
// A detector is silent by default. Pass [WithLogger] to attach an application-
// owned slog.Logger. Use [Detector.Scan] for handler-based processing and
// per-call statistics, or [Detector.Run] to iterate over individual findings and
// recoverable source errors. [WithAnalysis] enables both provider validation
// and credential analysis.
package detect
