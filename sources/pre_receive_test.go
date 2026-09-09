package sources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePreReceiveInput(t *testing.T) {
	const (
		oldSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		newSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	input := strings.Join([]string{
		oldSHA + " " + newSHA + " refs/heads/main",
		"",
		"  " + zeroOID + " " + newSHA + " refs/heads/feature  ",
		oldSHA + " " + zeroOID + " refs/heads/stale",
		"only two",
	}, "\n")

	updates, err := ParsePreReceiveInput(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, updates, 3)

	require.Equal(t, PreReceiveRefUpdate{OldValue: oldSHA, NewValue: newSHA, RefName: "refs/heads/main"}, updates[0])
	require.True(t, updates[1].IsCreate())
	require.Equal(t, "refs/heads/feature", updates[1].RefName)
	require.True(t, updates[2].IsDelete())
}

func TestPreReceiveLogArgs(t *testing.T) {
	const (
		oldSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		newSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	tests := []struct {
		name    string
		updates []PreReceiveRefUpdate
		want    []string
	}{
		{
			name:    "empty",
			updates: nil,
			want:    nil,
		},
		{
			name: "delete only",
			updates: []PreReceiveRefUpdate{
				{OldValue: oldSHA, NewValue: zeroOID, RefName: "refs/heads/stale"},
			},
			want: nil,
		},
		{
			name: "update",
			updates: []PreReceiveRefUpdate{
				{OldValue: oldSHA, NewValue: newSHA, RefName: "refs/heads/main"},
			},
			want: []string{oldSHA + ".." + newSHA},
		},
		{
			name: "create excludes existing history",
			updates: []PreReceiveRefUpdate{
				{OldValue: zeroOID, NewValue: newSHA, RefName: "refs/heads/feature"},
			},
			want: []string{newSHA, "--not", "--all"},
		},
		{
			name: "mixed update, create, and delete",
			updates: []PreReceiveRefUpdate{
				{OldValue: oldSHA, NewValue: newSHA, RefName: "refs/heads/main"},
				{OldValue: zeroOID, NewValue: newSHA, RefName: "refs/heads/feature"},
				{OldValue: oldSHA, NewValue: zeroOID, RefName: "refs/heads/stale"},
			},
			want: []string{oldSHA + ".." + newSHA, newSHA, "--not", "--all"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, PreReceiveLogArgs(tt.updates))
		})
	}
}

func TestIsZeroOID(t *testing.T) {
	require.True(t, isZeroOID(""))
	require.True(t, isZeroOID("0000000000000000000000000000000000000000"))
	require.True(t, isZeroOID(strings.Repeat("0", 64)))
	require.False(t, isZeroOID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	require.False(t, isZeroOID("0000000000000000000000000000000000000001"))
}
