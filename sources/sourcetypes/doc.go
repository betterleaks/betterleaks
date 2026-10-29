// Package sourcetypes holds the small types that every source and the scanner share: Fragment, Source
// and the attribute names. It has no third-party imports, so importing it does not pull in git, archive
// or cloud client code. Package sources re-exports everything here under its old names.
package sourcetypes

// InnerPathSeparator separates the path of an archive from the path of a file inside it.
const InnerPathSeparator = "!"
