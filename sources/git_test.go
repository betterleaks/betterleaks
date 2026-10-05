package sources

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/fatih/semgroup"
	"github.com/stretchr/testify/require"
)

func TestGitMergeSecrets(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(fmt.Sprintf("conflict=%t", conflict), func(t *testing.T) {
			repo := t.TempDir()
			git := func(args ...string) string {
				t.Helper()
				out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput()
				require.NoError(t, err, string(out))
				return strings.TrimSpace(string(out))
			}
			write := func(path, content string) {
				t.Helper()
				require.NoError(t, os.WriteFile(filepath.Join(repo, path), []byte(content), 0o600))
			}
			git("init", "-b", "main")
			git("config", "user.name", "Test User")
			git("config", "user.email", "test@example.com")
			git("config", "commit.gpgSign", "false")
			write("secret.txt", "header\nbase\n")
			git("add", ".")
			git("commit", "-qm", "base")
			git("checkout", "-qb", "side")
			write("secret.txt", "header\nside\n")
			write("side.txt", "SIDE_ONLY_SECRET\n")
			git("add", ".")
			git("commit", "-qm", "side secret")
			sideSHA := git("rev-parse", "HEAD")
			git("rm", "side.txt")
			git("commit", "-qm", "remove side secret")
			git("checkout", "-q", "main")
			if conflict {
				write("secret.txt", "header\nmain\n")
			} else {
				write("main.txt", "main\n")
			}
			git("add", ".")
			git("commit", "-qm", "main change")
			if conflict {
				out, err := exec.Command("git", "-C", repo, "merge", "--no-ff", "side", "-m", "merge").CombinedOutput()
				require.Error(t, err)
				require.Contains(t, string(out), "CONFLICT")
			} else {
				git("merge", "--no-ff", "side", "-m", "merge")
			}
			write("secret.txt", "header\nMERGE_ONLY_SECRET\n")
			git("add", ".")
			if conflict {
				git("commit", "-qm", "resolve merge")
			} else {
				git("commit", "--amend", "--no-edit")
			}
			mergeSHA := git("rev-parse", "HEAD")
			git("rm", "secret.txt")
			git("commit", "-qm", "remove merge secret")
			git("branch", "-D", "side")

			for _, workers := range []int{0, 1, 4} {
				for _, opts := range []string{"", "--all", mergeSHA + "^.." + mergeSHA} {
					t.Run(fmt.Sprintf("workers=%d/opts=%s", workers, opts), func(t *testing.T) {
						sema := semgroup.NewGroup(context.Background(), 4)
						var source Source
						if workers == 0 {
							cmd, err := NewGitLogCmdContext(t.Context(), repo, opts)
							require.NoError(t, err)
							source = &Git{Cmd: cmd, Sema: sema}
						} else {
							source = &ParallelGit{RepoPath: repo, LogOpts: opts, Workers: workers, Sema: sema}
						}
						var mu sync.Mutex
						var fragments []Fragment
						require.NoError(t, source.Fragments(t.Context(), func(f Fragment, err error) error {
							mu.Lock()
							defer mu.Unlock()
							fragments = append(fragments, f)
							return err
						}))
						require.NoError(t, sema.Wait())
						var merges, sides int
						for _, f := range fragments {
							if strings.Contains(f.Raw, "MERGE_ONLY_SECRET") {
								merges++
								require.Equal(t, mergeSHA, f.Attr(AttrGitSHA))
								require.Equal(t, "secret.txt", f.Attr(AttrPath))
								require.Equal(t, 2, f.StartLine)
							}
							if strings.Contains(f.Raw, "SIDE_ONLY_SECRET") {
								sides++
								require.Equal(t, sideSHA, f.Attr(AttrGitSHA))
							}
						}
						require.Equal(t, 1, merges)
						require.Equal(t, 1, sides, "history must still traverse the merged branch")
					})
				}
			}
		})
	}
}

// TODO: commenting out this test for now because it's flaky. Alternatives to consider to get this working:
// -- use `git stash` instead of `restore()`

// const repoBasePath = "../../testdata/repos/"

// const expectPath = "../../testdata/expected/"

// func TestGitLog(t *testing.T) {
// 	tests := []struct {
// 		source   string
// 		logOpts  string
// 		expected string
// 	}{
// 		{
// 			source:   filepath.Join(repoBasePath, "small"),
// 			expected: filepath.Join(expectPath, "git", "small.txt"),
// 		},
// 		{
// 			source:   filepath.Join(repoBasePath, "small"),
// 			expected: filepath.Join(expectPath, "git", "small-branch-foo.txt"),
// 			logOpts:  "--all foo...",
// 		},
// 	}

// 	err := moveDotGit("dotGit", ".git")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	defer func() {
// 		if err = moveDotGit(".git", "dotGit"); err != nil {
// 			t.Fatal(err)
// 		}
// 	}()

// 	for _, tt := range tests {
// 		files, err := git.GitLog(tt.source, tt.logOpts)
// 		if err != nil {
// 			t.Error(err)
// 		}

// 		var diffSb strings.Builder
// 		for f := range files {
// 			for _, tf := range f.TextFragments {
// 				diffSb.WriteString(tf.Raw(gitdiff.OpAdd))
// 			}
// 		}

// 		expectedBytes, err := os.ReadFile(tt.expected)
// 		if err != nil {
// 			t.Error(err)
// 		}
// 		expected := string(expectedBytes)
// 		if expected != diffSb.String() {
// 			// write string builder to .got file using os.Create
// 			err = os.WriteFile(strings.Replace(tt.expected, ".txt", ".got.txt", 1), []byte(diffSb.String()), 0644)
// 			if err != nil {
// 				t.Error(err)
// 			}
// 			t.Error("expected: ", expected, "got: ", diffSb.String())
// 		}
// 	}
// }

// func TestGitDiff(t *testing.T) {
// 	tests := []struct {
// 		source    string
// 		expected  string
// 		additions string
// 		target    string
// 	}{
// 		{
// 			source:    filepath.Join(repoBasePath, "small"),
// 			expected:  "this line is added\nand another one",
// 			additions: "this line is added\nand another one",
// 			target:    filepath.Join(repoBasePath, "small", "main.go"),
// 		},
// 	}

// 	err := moveDotGit("dotGit", ".git")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	defer func() {
// 		if err = moveDotGit(".git", "dotGit"); err != nil {
// 			t.Fatal(err)
// 		}
// 	}()

// 	for _, tt := range tests {
// 		noChanges, err := os.ReadFile(tt.target)
// 		if err != nil {
// 			t.Error(err)
// 		}
// 		err = os.WriteFile(tt.target, []byte(tt.additions), 0644)
// 		if err != nil {
// 			restore(tt.target, noChanges, t)
// 			t.Error(err)
// 		}

// 		files, err := git.GitDiff(tt.source, false)
// 		if err != nil {
// 			restore(tt.target, noChanges, t)
// 			t.Error(err)
// 		}

// 		for f := range files {
// 			sb := strings.Builder{}
// 			for _, tf := range f.TextFragments {
// 				sb.WriteString(tf.Raw(gitdiff.OpAdd))
// 			}
// 			if sb.String() != tt.expected {
// 				restore(tt.target, noChanges, t)
// 				t.Error("expected: ", tt.expected, "got: ", sb.String())
// 			}
// 		}
// 		restore(tt.target, noChanges, t)
// 	}
// }

// func restore(path string, data []byte, t *testing.T) {
// 	err := os.WriteFile(path, data, 0644)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// }

// func moveDotGit(from, to string) error {
// 	repoDirs, err := os.ReadDir("../../testdata/repos")
// 	if err != nil {
// 		return err
// 	}
// 	for _, dir := range repoDirs {
// 		if to == ".git" {
// 			_, err := os.Stat(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), "dotGit"))
// 			if os.IsNotExist(err) {
// 				// dont want to delete the only copy of .git accidentally
// 				continue
// 			}
// 			os.RemoveAll(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), ".git"))
// 		}
// 		if !dir.IsDir() {
// 			continue
// 		}
// 		_, err := os.Stat(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), from))
// 		if os.IsNotExist(err) {
// 			continue
// 		}

// 		err = os.Rename(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), from),
// 			fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), to))
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }
