package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPreReceiveFlagsRegistered(t *testing.T) {
	require.Equal(t, "false", gitCmd.Flags().Lookup("pre-receive").DefValue)
	require.Equal(t, "", gitCmd.Flags().Lookup("pre-receive-error-message").DefValue)
}

func TestPreReceiveHookRejectsPushWithLeak(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	bin := filepath.Join(t.TempDir(), "betterleaks")
	build := exec.Command("go", "build", "-o", bin, "./cmd/betterleaks")
	build.Dir = ".."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build betterleaks: %v\n%s", err, out)
	}

	repo := t.TempDir()
	runGitCommand(t, repo, "init", "--quiet")
	runGitCommand(t, repo, "config", "user.email", "test@example.com")
	runGitCommand(t, repo, "config", "user.name", "Test User")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "clean.txt"), []byte("nothing here\n"), 0o600))
	runGitCommand(t, repo, "add", ".")
	runGitCommand(t, repo, "commit", "--quiet", "-m", "base")
	oldSHA := runGitCommand(t, repo, "rev-parse", "HEAD")

	require.NoError(t, os.WriteFile(filepath.Join(repo, "creds.txt"),
		[]byte("token = \"glpat-ABCDEFGHIJKLMNOPQRST\"\n"), 0o600))
	runGitCommand(t, repo, "add", ".")
	runGitCommand(t, repo, "commit", "--quiet", "-m", "leak")
	newSHA := runGitCommand(t, repo, "rev-parse", "HEAD")

	run := func(stdin string) (string, error) {
		cmd := exec.Command(bin, "git", repo, "--pre-receive", "--no-banner",
			"--pre-receive-error-message", "BLOCKED on ${PROJECT}")
		cmd.Stdin = strings.NewReader(stdin)
		cmd.Env = append(os.Environ(), "PROJECT=my-service")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	out, err := run(oldSHA + " " + newSHA + " refs/heads/main\n")
	require.Error(t, err)
	require.Contains(t, out, "BLOCKED on my-service")
	require.Contains(t, out, "leaks found")

	out, err = run(newSHA + " " + strings.Repeat("0", 40) + " refs/heads/main\n")
	require.NoError(t, err, out)
	require.Contains(t, out, "no new commits to scan")
}

func TestPreReceiveHookRejectsActualPush(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	bin := filepath.Join(t.TempDir(), "betterleaks")
	build := exec.Command("go", "build", "-o", bin, "./cmd/betterleaks")
	build.Dir = ".."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build betterleaks: %v\n%s", err, out)
	}

	remote := filepath.Join(t.TempDir(), "remote.git")
	work := t.TempDir()
	runGitCommand(t, "", "init", "--bare", "--quiet", remote)
	runGitCommand(t, work, "init", "--quiet")
	runGitCommand(t, work, "config", "user.email", "test@example.com")
	runGitCommand(t, work, "config", "user.name", "Test User")
	runGitCommand(t, work, "remote", "add", "origin", remote)

	hook := "#!/bin/sh\nPROJECT=actual-push exec " + strconv.Quote(bin) +
		" git --pre-receive --no-banner --pre-receive-error-message 'BLOCKED on ${PROJECT}'\n"
	require.NoError(t, os.WriteFile(filepath.Join(remote, "hooks", "pre-receive"), []byte(hook), 0o700))

	require.NoError(t, os.WriteFile(filepath.Join(work, "clean.txt"), []byte("nothing here\n"), 0o600))
	runGitCommand(t, work, "add", ".")
	runGitCommand(t, work, "commit", "--quiet", "-m", "base")
	runGitCommand(t, work, "push", "--quiet", "origin", "HEAD:main")
	acceptedSHA := runGitCommand(t, remote, "rev-parse", "refs/heads/main")

	require.NoError(t, os.WriteFile(filepath.Join(work, "creds.txt"),
		[]byte("token = \"glpat-ABCDEFGHIJKLMNOPQRST\"\n"), 0o600))
	runGitCommand(t, work, "add", ".")
	runGitCommand(t, work, "commit", "--quiet", "-m", "leak")
	leakedSHA := runGitCommand(t, work, "rev-parse", "HEAD")

	push := exec.Command("git", "-C", work, "push", "origin", "HEAD:main")
	out, err := push.CombinedOutput()
	require.Error(t, err, "push containing a leak should be rejected")
	require.Contains(t, string(out), "BLOCKED on actual-push")
	require.Equal(t, acceptedSHA, runGitCommand(t, remote, "rev-parse", "refs/heads/main"))
	require.NotEqual(t, leakedSHA, acceptedSHA)
}

func runGitCommand(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	return strings.TrimSpace(string(out))
}
