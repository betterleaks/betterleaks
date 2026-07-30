package sources

import (
	"context"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/fatih/semgroup"
	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// collectPatchFragments scans a patch the way the diff command does and returns
// the fragments it yields, plus the first error reported.
func collectPatchFragments(t *testing.T, patch string, opts GitPatchOptions) ([]Fragment, error) {
	t.Helper()

	gitCmd, err := NewGitPatchCmd(strings.NewReader(patch), opts)
	require.NoError(t, err)

	src := &Git{
		Cmd:  gitCmd,
		Sema: semgroup.NewGroup(context.Background(), 1),
	}

	var (
		mu        sync.Mutex
		fragments []Fragment
		scanErr   error
	)
	// Fragments yields from several goroutines at once.
	err = src.Fragments(t.Context(), func(fragment Fragment, err error) error {
		mu.Lock()
		defer mu.Unlock()

		if err != nil {
			scanErr = err
			return nil
		}
		fragments = append(fragments, fragment)
		return nil
	})
	require.NoError(t, err)

	slices.SortFunc(fragments, func(a, b Fragment) int {
		if path := strings.Compare(a.Attr(AttrPath), b.Attr(AttrPath)); path != 0 {
			return path
		}
		return a.StartLine - b.StartLine
	})

	return fragments, scanErr
}

func TestAddedLineRuns(t *testing.T) {
	tests := map[string]struct {
		fragment *gitdiff.TextFragment
		expected []addedRun
	}{
		"zero-context hunk is one run at the hunk position": {
			fragment: &gitdiff.TextFragment{
				NewPosition: 3,
				Lines: []gitdiff.Line{
					{Op: gitdiff.OpAdd, Line: "one\n"},
					{Op: gitdiff.OpAdd, Line: "two\n"},
				},
			},
			expected: []addedRun{{raw: "one\ntwo\n", startLine: 3}},
		},
		"deletions do not consume post-image line numbers": {
			fragment: &gitdiff.TextFragment{
				NewPosition: 3,
				Lines: []gitdiff.Line{
					{Op: gitdiff.OpDelete, Line: "gone\n"},
					{Op: gitdiff.OpDelete, Line: "also gone\n"},
					{Op: gitdiff.OpAdd, Line: "new\n"},
				},
			},
			expected: []addedRun{{raw: "new\n", startLine: 3}},
		},
		"context lines split runs and advance the line number": {
			fragment: &gitdiff.TextFragment{
				NewPosition: 10,
				Lines: []gitdiff.Line{
					{Op: gitdiff.OpContext, Line: "ctx\n"}, // 10
					{Op: gitdiff.OpAdd, Line: "first\n"},   // 11
					{Op: gitdiff.OpContext, Line: "ctx\n"}, // 12
					{Op: gitdiff.OpContext, Line: "ctx\n"}, // 13
					{Op: gitdiff.OpAdd, Line: "second\n"},  // 14
					{Op: gitdiff.OpAdd, Line: "third\n"},   // 15
					{Op: gitdiff.OpContext, Line: "ctx\n"}, // 16
				},
			},
			expected: []addedRun{
				{raw: "first\n", startLine: 11},
				{raw: "second\nthird\n", startLine: 14},
			},
		},
		"deletions between added runs keep the runs separate": {
			fragment: &gitdiff.TextFragment{
				NewPosition: 1,
				Lines: []gitdiff.Line{
					{Op: gitdiff.OpAdd, Line: "a\n"},       // 1
					{Op: gitdiff.OpContext, Line: "ctx\n"}, // 2
					{Op: gitdiff.OpDelete, Line: "d\n"},
					{Op: gitdiff.OpAdd, Line: "b\n"}, // 3
				},
			},
			expected: []addedRun{
				{raw: "a\n", startLine: 1},
				{raw: "b\n", startLine: 3},
			},
		},
		"a hunk with no additions yields nothing": {
			fragment: &gitdiff.TextFragment{
				NewPosition: 4,
				Lines: []gitdiff.Line{
					{Op: gitdiff.OpDelete, Line: "gone\n"},
					{Op: gitdiff.OpContext, Line: "ctx\n"},
				},
			},
			expected: nil,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.expected, addedLineRuns(tt.fragment))
		})
	}
}

func TestGitPatchCmdMetadata(t *testing.T) {
	gitCmd, err := NewGitPatchCmd(strings.NewReader(""), GitPatchOptions{})
	require.NoError(t, err)

	assert.NoError(t, gitCmd.Wait(), "a patch has no process to wait on")
	assert.Equal(t, "patch", gitCmd.String())
	assert.False(t, gitCmd.CanReadBlobs(), "a patch has no repository to read blobs from")
}

func TestNewGitPatchCmd(t *testing.T) {
	const gitHeaderPatch = "diff --git a/api/api.go b/api/api.go\n" +
		"index 1234567..89abcde 100644\n" +
		"--- a/api/api.go\n" +
		"+++ b/api/api.go\n" +
		"@@ -0,0 +4,2 @@\n" +
		"+// a comment\n" +
		"+token := \"AKIALALEMEL33243OLIA\"\n"

	t.Run("an empty patch is a clean scan", func(t *testing.T) {
		fragments, scanErr := collectPatchFragments(t, "", GitPatchOptions{})

		assert.NoError(t, scanErr)
		assert.Empty(t, fragments)
	})

	t.Run("a git-formatted patch reports the real path and line numbers", func(t *testing.T) {
		fragments, scanErr := collectPatchFragments(t, gitHeaderPatch, GitPatchOptions{})

		require.NoError(t, scanErr)
		require.Len(t, fragments, 1)
		assert.Equal(t, "api/api.go", fragments[0].Attr(AttrPath))
		assert.Equal(t, 4, fragments[0].StartLine)
		assert.Equal(t, "// a comment\ntoken := \"AKIALALEMEL33243OLIA\"\n", fragments[0].Raw)
	})

	t.Run("only added lines are scanned", func(t *testing.T) {
		patch := "diff --git a/api/api.go b/api/api.go\n" +
			"--- a/api/api.go\n" +
			"+++ b/api/api.go\n" +
			"@@ -4,1 +4,1 @@\n" +
			"-removed := \"AKIALALEMEL33243OLIA\"\n" +
			"+added := \"ok\"\n"

		fragments, scanErr := collectPatchFragments(t, patch, GitPatchOptions{})

		require.NoError(t, scanErr)
		require.Len(t, fragments, 1)
		assert.Equal(t, "added := \"ok\"\n", fragments[0].Raw)
	})

	t.Run("commit details from the patch header are attached", func(t *testing.T) {
		patch := "commit 1b6da43b82b22e4eaa10bcf8ee591e91abbfc587\n" +
			"Author: Dev Eloper <dev@example.com>\n" +
			"Date:   Mon Jul 24 08:18:05 2023 +0000\n" +
			"\n    add a token\n\n" +
			gitHeaderPatch

		fragments, scanErr := collectPatchFragments(t, patch, GitPatchOptions{})

		require.NoError(t, scanErr)
		require.Len(t, fragments, 1)
		assert.Equal(t, "1b6da43b82b22e4eaa10bcf8ee591e91abbfc587", fragments[0].Attr(AttrGitSHA))
		assert.Equal(t, "Dev Eloper", fragments[0].Attr(AttrGitAuthorName))
		assert.Equal(t, "dev@example.com", fragments[0].Attr(AttrGitAuthorEmail))
		assert.Equal(t, "2023-07-24T08:18:05Z", fragments[0].Attr(AttrGitDate))
		assert.Equal(t, ResourceGitPatchContent, fragments[0].Attr(AttrResource))
	})

	t.Run("a patch without commit details still scans", func(t *testing.T) {
		fragments, scanErr := collectPatchFragments(t, gitHeaderPatch, GitPatchOptions{})

		require.NoError(t, scanErr)
		require.Len(t, fragments, 1)
		assert.Empty(t, fragments[0].Attr(AttrGitSHA))
		assert.Empty(t, fragments[0].Attr(AttrGitAuthorName))
	})

	t.Run("a deleted file yields nothing", func(t *testing.T) {
		patch := "diff --git a/api/api.go b/api/api.go\n" +
			"deleted file mode 100644\n" +
			"--- a/api/api.go\n" +
			"+++ /dev/null\n" +
			"@@ -1,1 +0,0 @@\n" +
			"-token := \"AKIALALEMEL33243OLIA\"\n"

		fragments, scanErr := collectPatchFragments(t, patch, GitPatchOptions{})

		require.NoError(t, scanErr)
		assert.Empty(t, fragments)
	})

	t.Run("every file in a multi-file patch is scanned", func(t *testing.T) {
		patch := gitHeaderPatch +
			"diff --git a/config/prod.env b/config/prod.env\n" +
			"--- a/config/prod.env\n" +
			"+++ b/config/prod.env\n" +
			"@@ -0,0 +1,1 @@\n" +
			"+KEY=value\n"

		fragments, scanErr := collectPatchFragments(t, patch, GitPatchOptions{})

		require.NoError(t, scanErr)
		require.Len(t, fragments, 2)
		assert.Equal(t, "api/api.go", fragments[0].Attr(AttrPath))
		assert.Equal(t, "config/prod.env", fragments[1].Attr(AttrPath))
	})

	t.Run("a patch not ending in a newline is still parsed", func(t *testing.T) {
		fragments, scanErr := collectPatchFragments(t,
			strings.TrimSuffix(gitHeaderPatch, "\n"), GitPatchOptions{})

		require.NoError(t, scanErr)
		require.Len(t, fragments, 1)
		assert.Equal(t, "api/api.go", fragments[0].Attr(AttrPath))
	})

	t.Run("a malformed patch is reported instead of silently skipped", func(t *testing.T) {
		// The hunk header promises more lines than the hunk contains, which
		// makes the parser abandon the patch.
		patch := "diff --git a/api/api.go b/api/api.go\n" +
			"--- a/api/api.go\n" +
			"+++ b/api/api.go\n" +
			"@@ -10,6 +10,8 @@\n" +
			" context\n" +
			"+token := \"AKIALALEMEL33243OLIA\"\n"

		_, scanErr := collectPatchFragments(t, patch, GitPatchOptions{})

		require.Error(t, scanErr)
		assert.Contains(t, scanErr.Error(), "malformed patch")
	})

	t.Run("a truncated patch is reported instead of silently skipped", func(t *testing.T) {
		patch := "diff --git a/api/api.go b/api/api.go\n" +
			"--- a/api/api.go\n" +
			"+++ b/api/api.go\n" +
			"@@ -0,0 +1,4 @@\n" +
			"+token := \"AKIALALEMEL33243OLIA\"\n"

		_, scanErr := collectPatchFragments(t, patch, GitPatchOptions{})

		require.Error(t, scanErr)
		assert.Contains(t, scanErr.Error(), "malformed patch")
	})

	t.Run("a patch that goes bad part way through fails the whole scan", func(t *testing.T) {
		// The first file parses fine and the second does not. The scan is
		// abandoned at that point rather than passing off what it managed to
		// read as a complete result, because the rest of the patch — and any
		// secret in it — was never seen.
		patch := gitHeaderPatch +
			"diff --git a/bad.go b/bad.go\n" +
			"--- a/bad.go\n" +
			"+++ b/bad.go\n" +
			"@@ -10,6 +10,8 @@\n" +
			" context\n"

		_, scanErr := collectPatchFragments(t, patch, GitPatchOptions{})

		require.Error(t, scanErr)
		assert.Contains(t, scanErr.Error(), "malformed patch")
	})

	t.Run("the sentinel entry is never scanned", func(t *testing.T) {
		fragments, scanErr := collectPatchFragments(t, patchSentinel, GitPatchOptions{})

		require.NoError(t, scanErr)
		assert.Empty(t, fragments)
	})

	t.Run("strip-components removes the a/ and b/ prefixes of a bare unified diff", func(t *testing.T) {
		// Without a "diff --git" header the prefixes cannot be told apart from
		// real directories, so they survive parsing and have to be stripped.
		patch := "--- a/api/api.go\n" +
			"+++ b/api/api.go\n" +
			"@@ -0,0 +4,1 @@\n" +
			"+token := \"AKIALALEMEL33243OLIA\"\n"

		fragments, scanErr := collectPatchFragments(t, patch, GitPatchOptions{})
		require.NoError(t, scanErr)
		require.Len(t, fragments, 1)
		assert.Equal(t, "b/api/api.go", fragments[0].Attr(AttrPath))

		fragments, scanErr = collectPatchFragments(t, patch, GitPatchOptions{StripComponents: 1})
		require.NoError(t, scanErr)
		require.Len(t, fragments, 1)
		assert.Equal(t, "api/api.go", fragments[0].Attr(AttrPath))
		assert.Equal(t, 4, fragments[0].StartLine)
	})
}

func TestStripPathComponents(t *testing.T) {
	tests := map[string]struct {
		path     string
		n        int
		expected string
	}{
		"no stripping":                {path: "b/api/api.go", n: 0, expected: "b/api/api.go"},
		"one component":               {path: "b/api/api.go", n: 1, expected: "api/api.go"},
		"two components":              {path: "b/api/api.go", n: 2, expected: "api.go"},
		"more than the path has":      {path: "b/api.go", n: 5, expected: "api.go"},
		"never strips to empty":       {path: "api.go", n: 1, expected: "api.go"},
		"trailing slash is preserved": {path: "b/", n: 1, expected: "b/"},
		"empty path":                  {path: "", n: 1, expected: ""},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.expected, stripPathComponents(tt.path, tt.n))
		})
	}
}

func TestNewlineTerminated(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected string
	}{
		"already terminated":  {input: "a\nb\n", expected: "a\nb\n"},
		"missing newline":     {input: "a\nb", expected: "a\nb\n"},
		"empty stays empty":   {input: "", expected: ""},
		"single byte":         {input: "a", expected: "a\n"},
		"trailing whitespace": {input: "a\n ", expected: "a\n \n"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			out, err := io.ReadAll(newlineTerminated(strings.NewReader(tt.input)))

			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(out))
		})
	}
}

func TestNewlineTerminatedOneByteAtATime(t *testing.T) {
	// io.ReadAll uses a generous buffer; a one-byte reader proves the appended
	// newline always has room.
	out, err := io.ReadAll(iotest{r: newlineTerminated(strings.NewReader("abc"))})

	require.NoError(t, err)
	assert.Equal(t, "abc\n", string(out))
}

// iotest reads a single byte at a time from the wrapped reader.
type iotest struct {
	r io.Reader
}

func (t iotest) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return t.r.Read(p[:1])
}
