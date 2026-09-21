package git

import (
	"os"
	"os/exec"
	"path/filepath"
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
	require.Equal(t, []PreReceiveRefUpdate{
		{OldValue: oldSHA, NewValue: newSHA, RefName: "refs/heads/main"},
		{OldValue: zeroOID, NewValue: newSHA, RefName: "refs/heads/feature"},
		{OldValue: oldSHA, NewValue: zeroOID, RefName: "refs/heads/stale"},
	}, updates)
	require.True(t, updates[1].IsCreate())
	require.True(t, updates[2].IsDelete())
}

func TestPreReceiveLogArgs(t *testing.T) {
	const (
		oldSHA  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		newSHA  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		blobSHA = "cccccccccccccccccccccccccccccccccccccccc"
	)
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
		{name: "empty"},
		{
			name:    "delete only",
			updates: []PreReceiveRefUpdate{{OldValue: oldSHA, NewValue: zeroOID, RefName: "refs/heads/stale"}},
		},
		{
			name:    "update",
			updates: []PreReceiveRefUpdate{{OldValue: oldSHA, NewValue: newSHA, RefName: "refs/heads/main"}},
			want:    []string{oldSHA + ".." + newSHA},
		},
		{
			name:    "create excludes existing history",
			updates: []PreReceiveRefUpdate{{OldValue: zeroOID, NewValue: newSHA, RefName: "refs/heads/feature"}},
			want:    []string{newSHA, "--not", "--all"},
		},
		{
			name: "mixed update create and delete",
			updates: []PreReceiveRefUpdate{
				{OldValue: oldSHA, NewValue: newSHA, RefName: "refs/heads/main"},
				{OldValue: zeroOID, NewValue: newSHA, RefName: "refs/heads/feature"},
				{OldValue: oldSHA, NewValue: zeroOID, RefName: "refs/heads/stale"},
			},
			want: []string{oldSHA + ".." + newSHA, newSHA, "--not", "--all"},
		},
		{
			name:    "non-commit new value is skipped",
			updates: []PreReceiveRefUpdate{{OldValue: zeroOID, NewValue: blobSHA, RefName: "refs/tags/blob-tag"}},
		},
		{
			name: "non-commit old value scans new like create",
			updates: []PreReceiveRefUpdate{
				{OldValue: oldSHA, NewValue: newSHA, RefName: "refs/heads/main"},
				{OldValue: blobSHA, NewValue: newSHA, RefName: "refs/tags/retagged"},
			},
			want: []string{oldSHA + ".." + newSHA, newSHA, "--not", "--all"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, PreReceiveLogArgs(tt.updates, resolve))
		})
	}
}

func TestPreReceiveLogArgsRejectsNonOIDInput(t *testing.T) {
	const newSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	require.Nil(t, PreReceiveLogArgs([]PreReceiveRefUpdate{
		{OldValue: zeroOID, NewValue: "--all", RefName: "refs/heads/evil"},
	}, nil))
	require.Nil(t, PreReceiveLogArgs([]PreReceiveRefUpdate{
		{OldValue: "HEAD", NewValue: newSHA, RefName: "refs/heads/main"},
	}, nil))
}

func TestOIDValidation(t *testing.T) {
	require.True(t, isZeroOID(""))
	require.True(t, isZeroOID(strings.Repeat("0", 40)))
	require.True(t, isZeroOID(strings.Repeat("0", 64)))
	require.False(t, isZeroOID(strings.Repeat("0", 39)+"1"))

	require.True(t, isHexOID(strings.Repeat("a", 40)))
	require.True(t, isHexOID(strings.Repeat("A", 40)))
	require.True(t, isHexOID(strings.Repeat("f", 64)))
	require.False(t, isHexOID(strings.Repeat("a", 39)))
	require.False(t, isHexOID(strings.Repeat("g", 40)))
	require.False(t, isHexOID("--all"))
}

func TestNewGitCommitResolver(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	repo := t.TempDir()
	runGitTestCommand(t, repo, "init", "--quiet")
	runGitTestCommand(t, repo, "config", "user.email", "test@example.com")
	runGitTestCommand(t, repo, "config", "user.name", "Test User")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "file.txt"), []byte("content\n"), 0o600))
	runGitTestCommand(t, repo, "add", ".")
	runGitTestCommand(t, repo, "commit", "--quiet", "-m", "base")

	commitSHA := runGitTestCommand(t, repo, "rev-parse", "HEAD")
	blobSHA := runGitTestCommand(t, repo, "rev-parse", "HEAD:file.txt")
	runGitTestCommand(t, repo, "tag", "-a", "blob-tag", "-m", "blob tag", blobSHA)
	blobTagSHA := runGitTestCommand(t, repo, "rev-parse", "blob-tag")
	runGitTestCommand(t, repo, "tag", "-a", "commit-tag", "-m", "commit tag", commitSHA)
	commitTagSHA := runGitTestCommand(t, repo, "rev-parse", "commit-tag")

	resolve := NewGitCommitResolver(t.Context(), repo)
	got, ok := resolve(commitSHA)
	require.True(t, ok)
	require.Equal(t, commitSHA, got)
	got, ok = resolve(commitTagSHA)
	require.True(t, ok)
	require.Equal(t, commitSHA, got)
	_, ok = resolve(blobTagSHA)
	require.False(t, ok)
	_, ok = resolve("--all")
	require.False(t, ok)
}

func runGitTestCommand(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	return strings.TrimSpace(string(out))
}
