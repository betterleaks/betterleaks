package sources

import (
	"github.com/betterleaks/betterleaks/logging"
	"github.com/rs/zerolog"
)

// Fragment represents a fragment of a source with its meta data
type Fragment struct {
	// Raw is the raw content of the fragment
	Raw string

	Bytes []byte

	// Indicates if this fragment is inherited from a finding
	InheritedFromFinding bool

	// StartLine is the line number this fragment starts on
	StartLine int

	// Attributes holds all source-specific metadata as flat key-value pairs.
	Attributes []Attribute
}

// Attr returns the value for the given key, or "" if not present.
func (f *Fragment) Attr(key string) string {
	for _, a := range f.Attributes {
		if a.Key == key {
			return a.Value
		}
	}
	return ""
}

// HasAttr returns true if the given key is present and non-empty.
func (f *Fragment) HasAttr(key string) bool {
	for _, a := range f.Attributes {
		if a.Key == key {
			return a.Value != ""
		}
	}
	return false
}

// Logger returns a zerolog.Logger enriched with the fragment's metadata.
func (f *Fragment) Logger() zerolog.Logger {
	l := logging.With().Str("path", f.Attr(AttrPath))
	if sha := f.Attr(AttrGitSHA); sha != "" {
		l = l.Str("commit", sha)
	}
	return l.Logger()
}
