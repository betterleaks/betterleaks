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
// Use [Detector.ValidateCredential] when the credential is already extracted.
// It runs the same provider pipeline without scanning or applying scan filters,
// and returns a sanitized report. [Credential] accepts named captures and one
// combination of companion secrets. Enable [WithValidation] for validation
// alone, or [WithAnalysis] to also analyze valid credentials.
package detect
