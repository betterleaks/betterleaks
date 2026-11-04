package sources

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/fatih/semgroup"
	"github.com/stretchr/testify/require"
)

func TestGitDisablesDiffHelpers(t *testing.T) {
	for _, configKey := range []string{"diff.probe.textconv", "diff.probe.command", "diff.external"} {
		t.Run(configKey, func(t *testing.T) {
			repo := t.TempDir()
			git := func(args ...string) string {
				t.Helper()
				cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", repo}, args...)...)
				cmd.Env = gitConfigIsolationEnv()
				out, err := cmd.CombinedOutput()
				require.NoError(t, err, string(out))
				return strings.TrimSpace(string(out))
			}
			write := func(name, content string) {
				t.Helper()
				require.NoError(t, os.WriteFile(filepath.Join(repo, name), []byte(content), 0o600))
			}
			git("init", "--quiet")
			git("config", "user.email", "test@example.com")
			git("config", "user.name", "Test User")
			write(".gitattributes", "*.txt diff=probe\n")
			write("file-0.txt", "value-0\n")
			git("add", ".")
			git("commit", "-qm", "first")
			firstCommit := git("rev-parse", "HEAD")
			write("file-1.txt", "value-1\n")
			git("add", ".")
			git("commit", "-qm", "second")
			secondCommit := git("rev-parse", "HEAD")
			write("file-0.txt", "value-staged\n")
			git("add", "file-0.txt")
			write("file-0.txt", "value-working\n")

			// Git runs helper commands through its shell, including on Windows.
			// Record execution and replace the content to verify scans use raw bytes.
			marker := filepath.Join(repo, ".git", "helper-marker")
			git("config", configKey, `sh -c 'printf invoked >> .git/helper-marker; printf "converted\n"'`)
			// Positive control: prove the fixture can actually execute the helper.
			git("log", "-p", "--ext-diff", "--textconv", "--all")
			require.FileExists(t, marker)
			require.NoError(t, os.Remove(marker))

			for _, tc := range []struct {
				name    string
				workers int
				opts    string
				mode    string
				want    string
			}{
				{name: "serial history", want: "value-0\n"},
				{name: "serial options", opts: "--all --ext-diff --textconv", want: "value-0\n"},
				{name: "serial path", opts: "--all --ext-diff --textconv -- file-0.txt", want: "value-0\n"},
				{name: "parallel history", workers: 4, want: "value-0\n"},
				{name: "parallel options", workers: 4, opts: "--all --ext-diff --textconv", want: "value-0\n"},
				{name: "single worker fallback", workers: 1, want: "value-0\n"},
				{name: "single worker options", workers: 1, opts: "--all --ext-diff --textconv", want: "value-0\n"},
				{name: "single worker path", workers: 1, opts: "--all --ext-diff --textconv -- file-0.txt", want: "value-0\n"},
				{name: "staged", mode: "staged", want: "value-staged\n"},
				{name: "working tree", mode: "working-tree", want: "value-working\n"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					t.Cleanup(func() { _ = os.Remove(marker) })
					sema := semgroup.NewGroup(t.Context(), 4)
					var source Source
					if tc.workers > 0 {
						source = &ParallelGit{RepoPath: repo, LogOpts: tc.opts, Workers: tc.workers, Sema: sema}
					} else {
						var cmd *GitCmd
						var err error
						if tc.mode == "" {
							cmd, err = NewGitLogCmdContext(t.Context(), repo, tc.opts)
						} else {
							cmd, err = NewGitDiffCmdContext(t.Context(), repo, tc.mode == "staged")
						}
						require.NoError(t, err)
						source = &Git{Cmd: cmd, Sema: sema}
					}
					var mu sync.Mutex
					var content []string
					err := source.Fragments(t.Context(), func(f Fragment, err error) error {
						mu.Lock()
						defer mu.Unlock()
						if f.Attr(AttrPath) == "file-0.txt" {
							content = append(content, f.Raw)
						}
						return err
					})
					workerErr := sema.Wait()
					require.NoFileExists(t, marker, "scanning must not execute Git diff helpers")
					require.NoError(t, err)
					require.NoError(t, workerErr)
					require.Equal(t, []string{tc.want}, content)
				})
			}

			// v1 enumerates and counts commits using rev-list rather than log.
			for _, tc := range []struct {
				opts string
				want []string
			}{
				{want: []string{secondCommit, firstCommit}},
				{opts: "--all --ext-diff --textconv", want: []string{secondCommit, firstCommit}},
				{opts: "--all --ext-diff --textconv -- file-0.txt", want: []string{firstCommit}},
			} {
				t.Run("commit selection/"+tc.opts, func(t *testing.T) {
					t.Cleanup(func() { _ = os.Remove(marker) })
					commits, err := listCommits(t.Context(), repo, tc.opts)
					require.NoFileExists(t, marker)
					require.NoError(t, err)
					require.Equal(t, tc.want, commits)
					count, err := commitCount(t.Context(), repo, tc.opts)
					require.NoFileExists(t, marker)
					require.NoError(t, err)
					require.Equal(t, len(tc.want), count)
				})
			}
		})
	}
}
