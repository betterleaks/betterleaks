package sources

import (
	"github.com/betterleaks/betterleaks/fragment"
)

// Fragment represents a fragment of a source with its meta data
type Fragment = fragment.Fragment

// CommitInfo captures metadata about a git commit.
type CommitInfo = fragment.CommitInfo

// RemoteInfo provides the info needed for reconstructing links from findings
type RemoteInfo = fragment.RemoteInfo

// FragmentsFunc is the type of function called by Fragments to yield the next
// fragment
type FragmentsFunc = fragment.FragmentsFunc

// Source is a thing that can yield fragments
type Source = fragment.Source
