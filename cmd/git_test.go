package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPreReceiveFlagsRegistered(t *testing.T) {
	require.NotNil(t, gitCmd.Flags().Lookup("pre-receive"))
	require.NotNil(t, gitCmd.Flags().Lookup("pre-receive-error-message"))

	preReceive := gitCmd.Flags().Lookup("pre-receive")
	require.Equal(t, "false", preReceive.DefValue)

	errMsg := gitCmd.Flags().Lookup("pre-receive-error-message")
	require.Equal(t, "", errMsg.DefValue)
}

// buildBetterleaksBinary compiles the CLI once for the current test so the
// pre-receive flow can be exercised end to end, including the os.Exit reject
// path that cannot be observed from an in-process call.
func buildBetterleaksBinary(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	bin := filepath.Join(t.TempDir(), "betterleaks")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = ".." // module root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build betterleaks: %v\n%s", err, out)
	}
	return bin
}

func gitCmdT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	return strings.TrimSpace(string(out))
}

// TestPreReceiveHookRejectsPushWithLeak drives the full pre-receive flow: it
// feeds a ref update on stdin, confirms the command exits non-zero when the
// pushed commit contains a secret, and confirms the custom error message is
// printed with environment variables expanded.
func TestPreReceiveHookRejectsPushWithLeak(t *testing.T) {
	bin := buildBetterleaksBinary(t)
	repo := t.TempDir()

	gitCmdT(t, repo, "-C", repo, "init", "--quiet")
	gitCmdT(t, repo, "-C", repo, "config", "user.email", "test@example.com")
	gitCmdT(t, repo, "-C", repo, "config", "user.name", "Test User")

	// Clean base commit.
	require.NoError(t, os.WriteFile(filepath.Join(repo, "clean.txt"), []byte("nothing here\n"), 0o600))
	gitCmdT(t, repo, "-C", repo, "add", ".")
	gitCmdT(t, repo, "-C", repo, "commit", "--quiet", "-m", "base")
	oldSHA := gitCmdT(t, repo, "-C", repo, "rev-parse", "HEAD")

	// Second commit introduces a detectable secret.
	require.NoError(t, os.WriteFile(filepath.Join(repo, "creds.txt"),
		[]byte("token = \"glpat-ABCDEFGHIJKLMNOPQRST\"\n"), 0o600))
	gitCmdT(t, repo, "-C", repo, "add", ".")
	gitCmdT(t, repo, "-C", repo, "commit", "--quiet", "-m", "leak")
	newSHA := gitCmdT(t, repo, "-C", repo, "rev-parse", "HEAD")

	run := func(stdin string) (string, error) {
		cmd := exec.Command(bin, "git", repo, "--pre-receive", "--no-banner",
			"--pre-receive-error-message", "BLOCKED on ${PROJECT}")
		cmd.Dir = repo
		cmd.Stdin = strings.NewReader(stdin)
		cmd.Env = append(os.Environ(), "PROJECT=my-service")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// Update push (old..new) with a leak must be rejected.
	out, err := run(oldSHA + " " + newSHA + " refs/heads/main\n")
	require.Error(t, err, "push with a leak should exit non-zero")
	require.Contains(t, out, "BLOCKED on my-service", "custom message with expanded env var")
	require.Contains(t, out, "leaks found")

	// Delete-only push has nothing to scan and must succeed.
	zero := strings.Repeat("0", 40)
	out, err = run(newSHA + " " + zero + " refs/heads/main\n")
	require.NoError(t, err, "delete-only push should succeed:\n%s", out)
	require.Contains(t, out, "no new commits to scan")
}
