package gogit

import (
	"errors"
	"fmt"
	"time"
)

// Limits bound the work spent on any one object, diff, or commit. Content that
// exceeds an item limit is reported as a source error and skipped, and the scan
// continues. A diff that exceeds its budget is scanned in full instead, which
// can only add findings. Structural limits reject corrupt or cyclic data.
const (
	defaultMaxBlobBytes   = 64 << 20  // Largest blob read for scanning.
	maxBlobBytesLimit     = 4 << 30   // Largest configurable MaxBlobBytes.
	maxCacheMiB           = 4096      // Largest configurable CacheMiB and DiskCacheMiB.
	maxWorkers            = 16        // Largest configurable Workers.
	maxTreeEntries        = 1_000_000 // Entries visited comparing one commit's trees.
	maxTreeChanges        = 100_000   // Changed paths in one commit.
	maxTreePathBytes      = 16 << 20  // Expanded path bytes in one commit.
	maxTreeDepth          = 256       // Directory nesting.
	maxDiffLines          = 1_000_000 // Lines in one diff pair; larger files are scanned in full.
	maxDeltaChain         = 10_000    // Delta links per object. Git packs at most 4,095.
	maxShallowBytes       = 8 << 20   // The shallow file of boundary commits.
	maxTagNesting         = 32        // Annotated tags naming annotated tags.
	maxUnreachableObjects = 8_000_000 // Object IDs held to classify reachability.
	maxReflogRecord       = 1 << 20   // Bytes in one reflog record.
	maxReflogDepth        = 64        // Directory nesting under logs/.
	maxPathFileBytes      = 4096      // .git, commondir, and gitdir pointer files.
	maxAlternatesBytes    = 64 << 10  // objects/info/alternates.
	binarySniffBytes      = 8000      // Like Git, a NUL in this prefix marks a binary.
)

// diffTimeout bounds one edit search. A diff that exceeds it is scanned in full.
// It is a variable so tests can shorten it.
var diffTimeout = time.Minute

// limitError reports content skipped because it exceeds a limit.
type limitError struct{ msg string }

func (e *limitError) Error() string { return e.msg }

func limitf(format string, args ...any) error {
	return &limitError{msg: fmt.Sprintf(format, args...)}
}

func isLimit(err error) bool {
	var limit *limitError
	return errors.As(err, &limit)
}
