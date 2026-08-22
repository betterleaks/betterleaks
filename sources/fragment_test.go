package sources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFragmentReleaseClearsLease(t *testing.T) {
	calls := 0
	fragment := &Fragment{Raw: []byte("secret")}
	fragment.release = func(got *Fragment) {
		calls++
		got.Raw = nil
	}

	fragment.Release()
	require.Equal(t, 1, calls)
	require.Nil(t, fragment.Raw)
	require.Nil(t, fragment.release)
}

func TestFileFragmentLeaseOutlivesCallback(t *testing.T) {
	source := &File{
		Content: strings.NewReader("leased content"),
		Path:    "lease.txt",
	}

	var leased *Fragment
	require.NoError(t, source.Fragments(t.Context(), func(fragment *Fragment, err error) error {
		require.NoError(t, err)
		leased = fragment
		return nil
	}))

	require.NotNil(t, leased)
	require.Equal(t, "leased content", string(leased.Raw))
	require.Equal(t, "lease.txt", leased.Attr(AttrPath))

	leased.Release()
	require.Nil(t, leased.Raw)
	require.Nil(t, leased.Attributes)
}

func TestCopiedFileFragmentCannotReleaseLease(t *testing.T) {
	fragment := newFileFragment("lease.txt")
	copy := *fragment

	require.PanicsWithValue(t, "sources: Release called on a copied Fragment lease", func() {
		copy.Release()
	})
	fragment.Release()
}
