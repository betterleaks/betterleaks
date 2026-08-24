package sources

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

type gitFragmentSnapshot struct {
	commit    string
	path      string
	raw       string
	startLine int
}

func TestGitWorkerCountPrecedence(t *testing.T) {
	source := new(Git)
	require.Equal(t, 1, source.workerCount(t.Context()))
	require.Equal(t, 6, source.workerCount(WithSourceWorkers(t.Context(), 6)))

	source.Workers = 3
	require.Equal(t, 3, source.workerCount(WithSourceWorkers(t.Context(), 6)))
}

func TestGitParallelHistoryMatchesSingleProcess(t *testing.T) {
	repoPath := createGitHubTestRepo(t)
	for i := 1; i <= 5; i++ {
		name := fmt.Sprintf("history-%d.txt", i)
		require.NoError(t, os.WriteFile(
			filepath.Join(repoPath, name),
			[]byte(fmt.Sprintf("value-%d\n", i)),
			0o600,
		))
		runGit(t, repoPath, "add", name)
		runGit(t, repoPath, "commit", "-m", fmt.Sprintf("history %d", i))
	}

	single := collectGitFragments(t, t.Context(), &Git{RepoPath: repoPath, Workers: 1})     //nolint:exhaustruct
	gitWorkers := collectGitFragments(t, t.Context(), &Git{RepoPath: repoPath, Workers: 3}) //nolint:exhaustruct
	sourceWorkers := collectGitFragments(
		t,
		WithSourceWorkers(t.Context(), 3),
		&Git{RepoPath: repoPath}, //nolint:exhaustruct
	)

	require.NotEmpty(t, single)
	require.Equal(t, single, gitWorkers)
	require.Equal(t, single, sourceWorkers)
}

func collectGitFragments(t *testing.T, ctx context.Context, source *Git) []gitFragmentSnapshot {
	t.Helper()

	var (
		mu        sync.Mutex
		fragments []gitFragmentSnapshot
	)
	require.NoError(t, source.Fragments(ctx, func(fragment Fragment, err error) error {
		if err != nil {
			return err
		}
		mu.Lock()
		fragments = append(fragments, gitFragmentSnapshot{
			commit:    fragment.Attr(AttrGitSHA),
			path:      fragment.Attr(AttrPath),
			raw:       fragment.Raw,
			startLine: fragment.StartLine,
		})
		mu.Unlock()
		return nil
	}))

	sort.Slice(fragments, func(i, j int) bool {
		if fragments[i].commit != fragments[j].commit {
			return fragments[i].commit < fragments[j].commit
		}
		if fragments[i].path != fragments[j].path {
			return fragments[i].path < fragments[j].path
		}
		if fragments[i].startLine != fragments[j].startLine {
			return fragments[i].startLine < fragments[j].startLine
		}
		return fragments[i].raw < fragments[j].raw
	})
	return fragments
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
