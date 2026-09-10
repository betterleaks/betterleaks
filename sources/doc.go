// Package sources defines the scanning protocol and the Reader, File, Files,
// and Git sources. A Source yields fragments of content with source attributes;
// it does not depend on the detector or its rule configuration.
//
// Provider integrations live in separate packages:
// github.com/betterleaks/betterleaks/v2/sources/github,
// github.com/betterleaks/betterleaks/v2/sources/gitlab,
// github.com/betterleaks/betterleaks/v2/sources/huggingface, and
// github.com/betterleaks/betterleaks/v2/sources/s3.
// Each provider's Source implements this package's Source interface.
//
// Common, filesystem, and Git attribute constants live here. Provider-specific
// attribute constants and resource values live with their providers. Their
// serialized string values are stable across the package split.
package sources
