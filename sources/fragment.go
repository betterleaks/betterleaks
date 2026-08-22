package sources

import (
	"github.com/betterleaks/betterleaks/logging"
	"github.com/rs/zerolog"
)

// Fragment represents a fragment of a source with its metadata. A Fragment
// received from Source.Fragments is a lease: ownership passes to the callback,
// which may retain it after the callback returns and must eventually call
// Release. Copying a leased Fragment does not transfer ownership: Release must
// be called on the original pointer supplied to the callback.
type Fragment struct {
	// Raw is the raw content of the fragment
	Raw []byte

	// Indicates if this fragment is inherited from a finding
	InheritedFromFinding bool

	// StartLine is the line number this fragment starts on (SetDefaults sets it to 1 if unset)
	StartLine int

	// Attributes holds all source-specific metadata
	Attributes map[string]string

	// release returns source-owned storage. It is deliberately unexported so
	// only the source that created a lease can install its recycler.
	release         func(*Fragment)
	owner           *Fragment
	bufferLease     *[]byte
	attributesLease map[string]string
}

// Release gives source-owned content and metadata back to their pools. Callers
// must invoke it exactly once when they no longer need the fragment and must
// not use the pointer afterward. Fragments constructed by library users have
// no recycler, so Release is a cheap no-op for them.
func (f *Fragment) Release() {
	if f == nil || f.release == nil {
		return
	}
	if f.owner != nil && f.owner != f {
		panic("sources: Release called on a copied Fragment lease")
	}
	release := f.release
	f.release = nil
	release(f)
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

// SetDefaults sets default fields that might not have been set on the fragment
func (f *Fragment) SetDefaults() {
	if f.StartLine == 0 {
		f.StartLine = 1 // Lines start at 1
	}
}
