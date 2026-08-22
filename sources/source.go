package sources

import "context"

// FragmentsFunc is the type of function called by Fragments to yield the next
// fragment. Ownership of a non-nil fragment transfers to the callback. The
// callback may retain it after returning and must eventually call Release
// exactly once. The fragment is invalid after Release.
type FragmentsFunc func(fragment *Fragment, err error) error

// SkipFunc decides whether to skip a fragment based on its attributes.
// Returns true to skip (discard), false to keep.
// Used by sources as a callback to decouple path/commit filtering from config.
type SkipFunc func(attrs map[string]string) bool

// PathSkipFunc is the allocation-free path-only form used while walking a
// filesystem. Sources with richer attributes continue to use SkipFunc.
type PathSkipFunc func(path string) bool

// Source is a thing that can yield fragments
type Source interface {
	// Fragments provides a filepath.WalkDir like interface for scanning the
	// fragments in the source. Implementations may invoke yield concurrently.
	Fragments(ctx context.Context, yield FragmentsFunc) error
}
