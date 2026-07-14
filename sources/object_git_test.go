package sources

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fatih/semgroup"
	"github.com/stretchr/testify/require"
)

func TestObjectGitPackedHistoryParity(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git executable not available")
	}
	repo := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Env = gitConfigIsolationEnv()
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
	}

	runGit("init", "-q")
	runGit("config", "user.name", "Test Author")
	runGit("config", "user.email", "test@example.com")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "secret.txt"), []byte("token=first-secret\n"), 0o600))
	runGit("add", ".")
	runGit("commit", "-qm", "first")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "secret.txt"), []byte("token=second-secret\n"), 0o600))
	runGit("commit", "-qam", "second")
	require.NoError(t, os.Mkdir(filepath.Join(repo, "moved"), 0o700))
	runGit("mv", "secret.txt", "moved/secret.txt")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "moved", "secret.txt"), []byte("token=second-secret\ntoken=third-secret\n"), 0o600))
	runGit("commit", "-qam", "move")
	runGit("tag", "-am", "release", "v1", "HEAD~1")
	runGit("gc", "--quiet")

	ctx := context.Background()
	legacyCmd, err := NewGitLogCmdContext(ctx, repo, "")
	require.NoError(t, err)
	legacy := &Git{Cmd: legacyCmd, Sema: semgroup.NewGroup(ctx, 4)}

	collect := func(src Source) string {
		t.Helper()
		var content strings.Builder
		var mu sync.Mutex
		require.NoError(t, src.Fragments(ctx, func(fragment Fragment, err error) error {
			mu.Lock()
			defer mu.Unlock()
			require.NoError(t, err)
			content.WriteString(fragment.Raw)
			require.NotEmpty(t, fragment.Attr(AttrGitSHA))
			require.Contains(t, []string{"secret.txt", "moved/secret.txt"}, fragment.Attr(AttrPath))
			return nil
		}))
		return content.String()
	}

	legacyContent := collect(legacy)
	objectContent := collect(&ObjectGit{RepoPath: repo})
	for _, secret := range []string{"first-secret", "second-secret", "third-secret"} {
		require.Contains(t, legacyContent, secret)
		require.Contains(t, objectContent, secret)
		require.Equal(t, 1, strings.Count(legacyContent, secret))
		require.Equal(t, 1, strings.Count(objectContent, secret))
	}
}

func TestObjectGitCorpus(t *testing.T) {
	repo := os.Getenv("BETTERLEAKS_BENCH_REPO")
	if repo == "" {
		t.Skip("set BETTERLEAKS_BENCH_REPO to run once against a corpus")
	}
	start := time.Now()
	var bytes atomic.Int64
	err := (&ObjectGit{RepoPath: repo}).Fragments(t.Context(), func(f Fragment, err error) error {
		bytes.Add(int64(len(f.Raw)))
		return err
	})
	require.NoError(t, err)
	t.Logf("elapsed=%s bytes=%d", time.Since(start), bytes.Load())
}

func BenchmarkGitSources(b *testing.B) {
	repo := os.Getenv("BETTERLEAKS_BENCH_REPO")
	if repo == "" {
		b.Skip("set BETTERLEAKS_BENCH_REPO to benchmark a repository")
	}

	b.Run("object", func(b *testing.B) {
		for range b.N {
			var bytes atomic.Int64
			err := (&ObjectGit{RepoPath: repo}).Fragments(b.Context(), func(f Fragment, err error) error {
				bytes.Add(int64(len(f.Raw)))
				return err
			})
			require.NoError(b, err)
		}
	})
	b.Run("legacy", func(b *testing.B) {
		for range b.N {
			cmd, err := NewGitLogCmdContext(b.Context(), repo, "")
			require.NoError(b, err)
			var bytes atomic.Int64
			err = (&Git{Cmd: cmd, Sema: semgroup.NewGroup(b.Context(), 40)}).Fragments(
				b.Context(), func(f Fragment, err error) error {
					bytes.Add(int64(len(f.Raw)))
					return err
				},
			)
			require.NoError(b, err)
		}
	})
}
