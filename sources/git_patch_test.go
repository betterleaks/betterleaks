package sources

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/internal/gitdiff"
)

func TestGitStreamFiltersBeforeContent(t *testing.T) {
	prefix := "diff --git a/skip.txt b/skip.txt\nnew file mode 100644\n--- /dev/null\n+++ b/skip.txt\n@@ -0,0 +1,3 @@\n"
	gate := &gitContentGate{header: strings.NewReader(prefix), content: strings.NewReader("+one\n+two\n+three\n")}
	err := readGitPatch(t.Context(), gate, func(file *gitdiff.File) (gitHunkFunc, error) {
		require.Equal(t, "skip.txt", file.NewName)
		gate.allowed = true
		return nil, nil
	})
	require.NoError(t, err)
}

func TestGitStreamBackslashPaths(t *testing.T) {
	// GitLab commit e4d07947f108878c8f3e5534f9b12a58c7ea2674 adds a file
	// named backslash. The upstream header parser rejects its closing quote.
	for _, name := range []string{"\\", "dir/\\\\", "quote\"\\", "\\134", "space and \\"} {
		t.Run(name, func(t *testing.T) {
			oldPath, newPath := strconv.Quote("a/"+name), strconv.Quote("b/"+name)
			patch := fmt.Sprintf("diff --git %s %s\nnew file mode 100644\nindex 000000000000..df743ce0a692\n--- /dev/null\n+++ %s\n@@ -0,0 +1 @@\n+example\n", oldPath, newPath, newPath)
			var fragments []string
			err := readGitPatch(t.Context(), strings.NewReader(patch), func(file *gitdiff.File) (gitHunkFunc, error) {
				require.Equal(t, name, file.NewName)
				return func(raw string, start int) error {
					require.Equal(t, 1, start)
					fragments = append(fragments, raw)
					return nil
				}, nil
			})
			require.NoError(t, err)
			require.Equal(t, []string{"example\n"}, fragments)
		})
	}
}

// Fail if the parser reads hunk content before the header callback can skip it.
type gitContentGate struct {
	header, content *strings.Reader
	allowed         bool
}

func (r *gitContentGate) Read(p []byte) (int, error) {
	if r.header.Len() > 0 {
		return r.header.Read(p)
	}
	if !r.allowed {
		return 0, errors.New("content read before filter")
	}
	return r.content.Read(p)
}

func TestGitStreamReadFailures(t *testing.T) {
	for _, body := range []string{"+one\n", "+one\n?two\n", "+one\n-two\n"} {
		t.Run(body, func(t *testing.T) {
			patch := "diff --git a/file b/file\n--- a/file\n+++ b/file\n@@ -0,0 +1,2 @@\n" + body
			err := readGitPatch(t.Context(), strings.NewReader(patch), func(*gitdiff.File) (gitHunkFunc, error) {
				return nil, nil
			})
			require.Error(t, err)
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, readGitPatch(ctx, strings.NewReader(""), nil), context.Canceled)
}

func TestGitStreamPreservesMultilineHunk(t *testing.T) {
	content := "begin\n" + strings.Repeat("middle\n", 40000) + "end"
	patch := fmt.Sprintf("diff --git a/file b/file\nnew file mode 100644\n--- /dev/null\n+++ b/file\n@@ -0,0 +1,%d @@\n+%s\n\\ No newline at end of file\n", strings.Count(content, "\n")+1, strings.ReplaceAll(content, "\n", "\n+"))
	var got []string
	require.NoError(t, readGitPatch(t.Context(), strings.NewReader(patch), func(*gitdiff.File) (gitHunkFunc, error) {
		return func(raw string, start int) error {
			require.Equal(t, 1, start)
			got = append(got, raw)
			return nil
		}, nil
	}))
	require.Equal(t, []string{content}, got)
}

func BenchmarkReadGitPatch(b *testing.B) {
	const lines = 32768
	patch := []byte(fmt.Sprintf("diff --git a/file b/file\n--- a/file\n+++ b/file\n@@ -1,%d +1,%d @@\n", lines, lines) + strings.Repeat("-old ordinary line\n", lines) + strings.Repeat("+new ordinary line\n", lines))
	for _, skip := range []bool{false, true} {
		b.Run(fmt.Sprintf("skip=%t", skip), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(patch)))
			for b.Loop() {
				err := readGitPatch(context.Background(), bytes.NewReader(patch), func(*gitdiff.File) (gitHunkFunc, error) {
					if skip {
						return nil, nil
					}
					return func(raw string, _ int) error {
						if len(raw) != lines*len("new ordinary line\n") {
							return io.ErrUnexpectedEOF
						}
						return nil
					}, nil
				})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkParseGitScanHeader(b *testing.B) {
	const header = "diff --git a/dir/file.txt b/dir/file.txt\nindex 1c23fcc..40a1b33 100644\n--- a/dir/file.txt\n+++ b/dir/file.txt\n"
	b.ReportAllocs()
	for b.Loop() {
		file, err := parseGitScanHeader(header)
		if err != nil {
			b.Fatal(err)
		}
		if file.NewName != "dir/file.txt" {
			b.Fatal("incorrect file name")
		}
	}
}

func BenchmarkReadGitPatchManyFiles(b *testing.B) {
	const files = 1000
	var patch strings.Builder
	for i := range files {
		fmt.Fprintf(&patch, "diff --git a/file%d b/file%d\nindex 1c23fcc..40a1b33 100644\n--- a/file%d\n+++ b/file%d\n@@ -1 +1 @@\n-old\n+new\n", i, i, i, i)
	}
	input := patch.String()
	for _, skip := range []bool{false, true} {
		b.Run(fmt.Sprintf("skip=%t", skip), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(input)))
			for b.Loop() {
				var seen int
				err := readGitPatch(context.Background(), strings.NewReader(input), func(*gitdiff.File) (gitHunkFunc, error) {
					seen++
					if skip {
						return nil, nil
					}
					return func(raw string, _ int) error {
						if raw != "new\n" {
							return errors.New("incorrect hunk content")
						}
						return nil
					}, nil
				})
				if err != nil {
					b.Fatal(err)
				}
				if seen != files {
					b.Fatalf("parsed %d files, want %d", seen, files)
				}
			}
		})
	}
}
