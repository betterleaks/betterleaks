//go:build unix

package sources

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGitIsolationManyWorktrees(t *testing.T) {
	// Limit only the child process; other package tests may run in parallel.
	const childEnv = "BETTERLEAKS_TEST_LOW_NOFILE"
	if os.Getenv(childEnv) != "1" {
		exe, err := os.Executable()
		require.NoError(t, err)
		cmd := exec.CommandContext(t.Context(), exe, "-test.run=^TestGitIsolationManyWorktrees$", "-test.v")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", out)
		return
	}
	var limit syscall.Rlimit
	require.NoError(t, syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit))
	limit.Cur = min(limit.Max, 128)
	require.NoError(t, syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit))

	f := newGitFixture(t)
	f.write("file.txt", "BASE\n")
	sha := f.commit("base")
	linked := filepath.Join(t.TempDir(), "linked")
	f.git("worktree", "add", "-q", "-b", "linked", linked)
	require.NoError(t, os.WriteFile(filepath.Join(linked, "file.txt"), []byte("STAGED\n"), 0o600))
	f.gitIn(linked, "", "add", "file.txt")

	// Populate detached worktree metadata without spawning hundreds of Git
	// processes. These worktrees need no checkout for history scans.
	for i := range 256 {
		dir := filepath.Join(f.path, ".git", "worktrees", fmt.Sprintf("worktree-%03d", i))
		require.NoError(t, os.MkdirAll(dir, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "HEAD"), []byte(sha+"\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "gitdir"), []byte(filepath.Join(dir, "checkout", ".git")+"\n"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "commondir"), []byte("../..\n"), 0o600))
	}
	for _, source := range []string{f.path, linked} {
		for _, withIndex := range []bool{false, true} {
			t.Run(fmt.Sprintf("linked=%t/index=%t", source == linked, withIndex), func(t *testing.T) {
				r, err := openGitRepo(t.Context(), source, GitOptions{}, withIndex)
				require.NoError(t, err)
				defer r.Close()
				out, err := r.command(t.Context(), "rev-parse", "--verify", "HEAD").CombinedOutput()
				require.NoError(t, err, "%s", out)
				require.Equal(t, sha, strings.TrimSpace(string(out)))
				if withIndex {
					out, err = r.command(t.Context(), "diff", "--cached", "--name-only").CombinedOutput()
					require.NoError(t, err, "%s", out)
					want := f.gitIn(source, "", "diff", "--cached", "--name-only")
					require.Equal(t, want, strings.TrimSpace(string(out)))
				}
			})
		}
	}
}
