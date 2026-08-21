//go:build !race

package sources

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFileFragmentLeaseLifecycleDoesNotAllocate(t *testing.T) {
	cycle := func() {
		bufferLease := getBuffer()
		fragment := newFileFragment("lease.txt")
		fragment.Raw = (*bufferLease)[:1]
		fragment.bufferLease = bufferLease
		fragment.Release()
	}

	cycle() // Warm every pool before measuring its steady state.
	require.Zero(t, testing.AllocsPerRun(500, cycle))
}
