package sources

import (
	"os/exec"
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
		// blobSHA stands in for a tag that points directly at a blob/tree and
		// therefore does not peel to a commit.
		blobSHA = "cccccccccccccccccccccccccccccccccccccccc"
	)

	// resolve treats every value as a commit except blobSHA.
	resolve := func(oid string) (string, bool) {
		if oid == blobSHA {
			return "", false
		}
		return oid, true
	}

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
		{
			name: "non-commit ref is skipped",
			updates: []PreReceiveRefUpdate{
				{OldValue: zeroOID, NewValue: blobSHA, RefName: "refs/tags/blob-tag"},
			},
			want: nil,
		},
		{
			name: "non-commit ref does not trigger not-all",
			updates: []PreReceiveRefUpdate{
				{OldValue: oldSHA, NewValue: newSHA, RefName: "refs/heads/main"},
				{OldValue: zeroOID, NewValue: blobSHA, RefName: "refs/tags/blob-tag"},
			},
			want: []string{oldSHA + ".." + newSHA},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, PreReceiveLogArgs(tt.updates, resolve))
		})
	}
}

func TestPreReceiveLogArgsNilResolver(t *testing.T) {
	const (
		oldSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		newSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	// A nil resolver uses new values verbatim.
	got := PreReceiveLogArgs([]PreReceiveRefUpdate{
		{OldValue: oldSHA, NewValue: newSHA, RefName: "refs/heads/main"},
	}, nil)
	require.Equal(t, []string{oldSHA + ".." + newSHA}, got)
}

func TestIsZeroOID(t *testing.T) {
	require.True(t, isZeroOID(""))
	require.True(t, isZeroOID("0000000000000000000000000000000000000000"))
	require.True(t, isZeroOID(strings.Repeat("0", 64)))
	require.False(t, isZeroOID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	require.False(t, isZeroOID("0000000000000000000000000000000000000001"))
}

func TestNewGitCommitResolver(t *testing.T) {
	repo := newGitTestRepo(t, 1)

	revParse := func(rev string) string {
		t.Helper()
		out, err := exec.Command("git", "-C", repo, "rev-parse", rev).Output()
		require.NoError(t, err)
		return strings.TrimSpace(string(out))
	}

	commitSHA := revParse("HEAD")

	// A tag object pointing directly at a blob has no commit to scan.
	blobSHA := revParse("HEAD:file-0.txt")
	runGitTestCommand(t, repo, "tag", "-a", "blob-tag", "-m", "blob tag", blobSHA)
	blobTagSHA := revParse("blob-tag")

	// An annotated tag pointing at a commit should peel to that commit.
	runGitTestCommand(t, repo, "tag", "-a", "commit-tag", "-m", "commit tag", commitSHA)
	commitTagSHA := revParse("commit-tag")

	resolve := NewGitCommitResolver(t.Context(), repo)

	got, ok := resolve(commitSHA)
	require.True(t, ok)
	require.Equal(t, commitSHA, got)

	got, ok = resolve(commitTagSHA)
	require.True(t, ok, "annotated tag on a commit should peel to the commit")
	require.Equal(t, commitSHA, got)

	_, ok = resolve(blobTagSHA)
	require.False(t, ok, "tag pointing at a blob should not resolve to a commit")

	_, ok = resolve(strings.Repeat("0", 40))
	require.False(t, ok, "unknown object should not resolve")
}
