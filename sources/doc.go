// Package sources defines the scanning protocol and the Reader source.
// A Source yields fragments of content with source attributes; it does not
// depend on the scanner or its rule configuration. This package and its
// dependencies use only the standard library and Betterleaks' internal code.
//
// Concrete sources live in subpackages: filesystem provides File and Files,
// web provides URL, gitpatch provides GitDiff, and gogit reads Git repositories.
// Provider integrations live in github, gitlab, huggingface, s3, and container.
// Import the implementation needed and pass it to scan.Scanner or
// pipeline.Pipeline. The auto package classifies targets without constructing
// a source; scm provides platform metadata independently of scm/clone.
//
// Common, filesystem, and Git attribute constants live here. Provider-specific
// attribute constants and resource values live with their providers. Their
// serialized string values are stable across the package split.
package sources
