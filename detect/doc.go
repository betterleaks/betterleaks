// Package detect provides the reusable secret-detection engine.
//
// Load Betterleaks' built-in rules with config.Default, or load an application-
// owned betterleaks.toml with config.LoadFile. Pass the resulting config.Config
// to [NewDetector]. Rules can also be constructed directly: config.Rule.Regex
// and config.Rule.Path hold pattern strings. NewDetector snapshots this data and
// creates private regex objects using the currently selected regexp engine.
// Backend compilation remains lazy unless [WithPrecompile] is set.
//
// A detector is silent by default. Pass [WithLogger] to attach an application-
// owned slog.Logger. Use [Detector.Scan] for handler-based processing and
// per-call statistics, or [Detector.Run] to iterate over individual findings and
// recoverable source errors. [WithAnalysis] enables both provider validation
// and credential analysis.
//
// For already-extracted credentials, use the public validate package. Both
// packages use the same provider execution pipeline.
package detect
