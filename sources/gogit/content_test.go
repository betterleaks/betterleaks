//nolint:exhaustruct // Test fixtures specify only the fields relevant to each scenario.
package gogit

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Test the edit script rather than mirroring the diff implementation: emitted
// text must refer to the stated destination lines, and everything not emitted
// must be an ordered subsequence of the parent. No possible addition is lost.
func checkLineAdditions(t *testing.T, src, dst string) {
	t.Helper()
	split := func(text string) []string {
		if text == "" {
			return nil
		}
		lines := strings.SplitAfter(text, "\n")
		if lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		return lines
	}
	current := split(dst)
	added := make([]bool, len(current))
	previousEnd := 0
	var differ lineDiffer
	err := differ.additions(t.Context(), src, dst, func(text string, line int) error {
		start := line - 1
		n := len(split(text))
		require.GreaterOrEqual(t, start, previousEnd)
		require.LessOrEqual(t, start+n, len(current))
		require.Equal(t, strings.Join(current[start:start+n], ""), text)
		for i := start; i < start+n; i++ {
			added[i] = true
		}
		previousEnd = start + n
		return nil
	})
	require.NoError(t, err)
	old := split(src)
	at := 0
	for i, text := range current {
		if added[i] {
			continue
		}
		for at < len(old) && old[at] != text {
			at++
		}
		require.Less(t, at, len(old), "retained line not found in ordered parent")
		at++
	}
}

func TestLineAdditions(t *testing.T) {
	rng := rand.New(rand.NewPCG(13, 27))
	words := []string{"one\n", "two\n", "two\n", "\n", "unicode-世界\n", "crlf\r\n"}
	for range 500 {
		var src, dst strings.Builder
		for range rng.IntN(60) {
			src.WriteString(words[rng.IntN(len(words))])
		}
		for range rng.IntN(60) {
			dst.WriteString(words[rng.IntN(len(words))])
		}
		checkLineAdditions(t, src.String(), dst.String())
		checkLineAdditions(t, strings.TrimSuffix(src.String(), "\n"), strings.TrimSuffix(dst.String(), "\n"))
	}
	// Large complete rewrites must not spend quadratic time on unmatched lines.
	var old, current strings.Builder
	for i := range 70000 {
		fmt.Fprintf(&old, "old-%d\n", i)
		fmt.Fprintf(&current, "new-%d\n", i)
	}
	checkLineAdditions(t, old.String(), current.String())
	// Shared tokens cross the Unicode surrogate boundary as well. The final
	// insertion must retain its original coordinate after matching all of them.
	var additions []string
	require.NoError(t, lineAdditions(t.Context(), old.String(), old.String()+"secret\n", func(raw string, line int) error {
		require.Equal(t, 70001, line)
		additions = append(additions, raw)
		return nil
	}))
	require.Equal(t, []string{"secret\n"}, additions)
	// Changes beyond the token limit are scanned whole rather than diffed.
	require.NoError(t, lineAdditions(t.Context(), strings.Repeat("x\n", 1_000_000), "", func(string, int) error { t.Fatal("an empty file yielded"); return nil }))
	additions = nil
	require.NoError(t, lineAdditions(t.Context(), strings.Repeat("x\n", 1_000_000), "y\nx\nz\n", func(raw string, line int) error {
		require.Equal(t, 1, line)
		additions = append(additions, raw)
		return nil
	}))
	require.Equal(t, []string{"y\nx\nz\n"}, additions)
	// Lines shared at both ends are trimmed first, so one edit to a file over
	// the limit is still diffed, at its original line.
	var big strings.Builder
	for i := range 1_000_000 {
		fmt.Fprintf(&big, "line-%d\n", i)
	}
	edited := strings.Replace(big.String(), "line-500000\n", "secret\n", 1)
	additions = nil
	require.NoError(t, lineAdditions(t.Context(), big.String(), edited, func(raw string, line int) error {
		require.Equal(t, 500001, line)
		additions = append(additions, raw)
		return nil
	}))
	require.Equal(t, []string{"secret\n"}, additions)
	stop := errors.New("stop")
	require.ErrorIs(t, lineAdditions(t.Context(), "old\n", "new\n", func(string, int) error { return stop }), stop)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, lineAdditions(ctx, "old\n", "new\n", func(string, int) error { t.Fatal("emit after cancel"); return nil }), context.Canceled)
}

// A blank line inside new text must not anchor the diff to one of the blank
// lines it replaces: that splits a private key into two fragments, neither of
// which matches a rule. ruby/ruby's c9dc0164 adds such a key.
func TestLineAdditionsKeepNewBlocksWhole(t *testing.T) {
	block := func(i int) string { return fmt.Sprintf("  def test_%d\n    check %d\n  end\n\n", i, i) }
	key := "  def test_encrypted\n    pem = <<~EOF\n    -----BEGIN EC PRIVATE KEY-----\n    Proc-Type: 4,ENCRYPTED\n" +
		"    DEK-Info: AES-128-CBC,85743EB6FAC9EA76\n\n    MHcCAQEEIIq3fN0QJkVfSZpXXbpl8rUn\n    -----END EC PRIVATE KEY-----\n    EOF\n"
	var old, current strings.Builder
	for i := range 40 {
		old.WriteString(block(i))
		switch {
		case i == 20:
			current.WriteString(key + "  end\n\n")
		case i < 20 || i > 23:
			current.WriteString(block(i))
		}
	}
	var additions []string
	require.NoError(t, lineAdditions(t.Context(), old.String(), current.String(), func(raw string, line int) error {
		require.Equal(t, 81, line)
		additions = append(additions, raw)
		return nil
	}))
	require.Equal(t, []string{key}, additions)
}

type diffCancelContext struct {
	context.Context
	onCheck func()
}

func (c diffCancelContext) Err() error {
	c.onCheck()
	return c.Context.Err()
}

func TestLineAdditionsCancelDuringPreprocessing(t *testing.T) {
	const padding = 2048
	const markerLine = padding + 1
	body := strings.Repeat("\n", padding) + "marker\n" + strings.Repeat("\n", padding)
	src, dst := "old-start\n"+body+"old-end\n", "new-start\n"+body+"new-end\n"
	for _, tc := range []struct {
		name       string
		started    func(*lineDiffer) bool
		unfinished func(*lineDiffer) bool
	}{
		{
			name:       "parent tokenization",
			started:    func(d *lineDiffer) bool { return d.ids["old-start\n"] != 0 },
			unfinished: func(d *lineDiffer) bool { return d.old[markerLine] == 0 },
		},
		{
			name:       "destination tokenization",
			started:    func(d *lineDiffer) bool { return len(d.inNew) > 0 && d.inNew[0] > 0 },
			unfinished: func(d *lineDiffer) bool { return d.current[markerLine] == 0 },
		},
		{
			name: "parent pruning",
			started: func(d *lineDiffer) bool {
				return d.ids["\n"] != 0 && d.old[0] == d.ids["\n"]
			},
			unfinished: func(d *lineDiffer) bool { return d.old[markerLine] == d.ids["marker\n"] },
		},
		{
			name:       "destination pruning",
			started:    func(d *lineDiffer) bool { return len(d.positions) > 0 && d.positions[0] > 0 },
			unfinished: func(d *lineDiffer) bool { return d.positions[markerLine] == 0 },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var d lineDiffer
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var canceled, unfinished bool
			// Observe scratch progress only from Err, on the same goroutine as
			// the diff. Cancellation must be checked while the phase is still
			// running, not just after all its work. This avoids timing thresholds
			// and does not depend on the precise polling interval.
			observed := diffCancelContext{Context: ctx, onCheck: func() {
				if !canceled && tc.started(&d) {
					canceled, unfinished = true, tc.unfinished(&d)
					cancel()
				}
			}}
			err := d.additions(observed, src, dst, func(string, int) error {
				t.Fatal("emitted content after cancellation during preprocessing")
				return nil
			})
			require.ErrorIs(t, err, context.Canceled)
			require.True(t, canceled, "must reach the selected phase")
			require.True(t, unfinished, "must check cancellation before finishing the phase")
		})
	}
}

func FuzzLineAdditions(f *testing.F) {
	f.Add("old\ncommon\n", "new\ncommon\n")
	f.Add("", "no final newline")
	f.Add("a\nb\na\n", "b\na\nb\n")
	f.Fuzz(func(t *testing.T, old, current string) {
		if len(old)+len(current) > 8192 {
			t.Skip()
		}
		checkLineAdditions(t, old, current)
	})
}

func TestExpensiveDiffBudget(t *testing.T) {
	var src, dst strings.Builder
	// Every line exists in both versions, defeating unmatched-line pruning.
	// Reverse order also avoids the diff engine's half-match shortcut.
	for i := range 30000 {
		fmt.Fprintf(&src, "line %d\n", i)
		fmt.Fprintf(&dst, "line %d\n", 29999-i)
	}
	t.Run("budget", func(t *testing.T) {
		// An exhausted search scans the whole file instead of an approximate patch.
		defer func(timeout time.Duration) { diffTimeout = timeout }(diffTimeout)
		diffTimeout = 50 * time.Millisecond
		var additions []string
		require.NoError(t, lineAdditions(t.Context(), src.String(), dst.String(), func(raw string, line int) error {
			require.Equal(t, 1, line)
			additions = append(additions, raw)
			return nil
		}))
		require.Equal(t, []string{dst.String()}, additions)
	})
	for _, cancelDuringSearch := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%v", cancelDuringSearch), func(t *testing.T) {
			// An earlier caller deadline shortens the search; cancellation is
			// reported rather than scanning the whole file.
			ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
			defer cancel()
			if cancelDuringSearch {
				timer := time.AfterFunc(50*time.Millisecond, cancel)
				defer timer.Stop()
			}
			started := time.Now()
			var whole bool
			err := lineAdditions(ctx, src.String(), dst.String(), func(raw string, _ int) error {
				whole = raw == dst.String()
				return nil
			})
			switch {
			case cancelDuringSearch:
				require.ErrorIs(t, err, context.Canceled)
			case err == nil:
				// The shortened search can end just before the deadline fires.
				require.True(t, whole, "an exhausted search scans the whole file")
			default:
				require.ErrorIs(t, err, context.DeadlineExceeded)
			}
			require.Less(t, time.Since(started), 5*time.Second)
		})
	}
}

func lineAdditions(ctx context.Context, src, dst string, emit func(string, int) error) error {
	var d lineDiffer
	return d.additions(ctx, src, dst, emit)
}
