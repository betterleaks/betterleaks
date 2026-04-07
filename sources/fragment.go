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

	// Attributes holds all source-specific metadata
	Attributes map[string]string
}

func (f *Fragment) SetAttr(key, value string) {
	if f.Attributes == nil {
		f.Attributes = make(map[string]string)
	}
	f.Attributes[key] = value
}

func (f *Fragment) Attr(key string) string {
	if f.Attributes == nil {
		return ""
	}
	return f.Attributes[key]
}

// Logger returns a zerolog.Logger enriched with the fragment's metadata.
func (f *Fragment) Logger() zerolog.Logger {
	l := logging.With().Str("path", f.Attr(AttrPath))
	if sha := f.Attr(AttrGitSHA); sha != "" {
		l = l.Str("commit", sha)
	}
	return l.Logger()
}
