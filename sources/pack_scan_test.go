package sources

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// TestApplyDelta round-trips a synthetic delta and checks reconstruction.
func TestApplyDelta(t *testing.T) {
	base := []byte("line one\nline two\nline three\nline four\n")
	target := []byte("line one\nline 2 changed\nline three\nline four\n")

	delta := makeInsertDelta(len(base), target)
	tgtSize, hdr, err := deltaTargetSize(delta)
	if err != nil {
		t.Fatal(err)
	}
	if int(tgtSize) != len(target) {
		t.Fatalf("target size %d != %d", tgtSize, len(target))
	}
	out := make([]byte, tgtSize)
	if err := applyDelta(base, delta[hdr:], out); err != nil {
		t.Fatal(err)
	}
	if string(out) != string(target) {
		t.Fatalf("reconstruct mismatch:\n got %q\nwant %q", out, target)
	}
}

// TestEmitDedupRuns verifies runs of unseen lines coalesce and seen lines split.
func TestEmitDedupRuns(t *testing.T) {
	lines := newLineSeen()
	// Pre-seed line "bbb" as already seen.
	lines.markNew([]byte("bbb"))

	content := []byte("aaa\nbbb\nccc\nddd\n")
	var got []string
	err := emitDedupRuns(content, map[string]string{}, lines, func(f Fragment, err error) error {
		got = append(got, f.Raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// One seen line ("bbb") is bridged, so all four lines coalesce into a
	// single run that ends at the last new line.
	if len(got) != 1 {
		t.Fatalf("want 1 bridged run, got %d: %q", len(got), got)
	}
	if got[0] != "aaa\nbbb\nccc\nddd\n" {
		t.Fatalf("run = %q, want full content", got[0])
	}
}

func TestEmitDedupRunsSplitsOnLongGap(t *testing.T) {
	lines := newLineSeen()
	// Seed a long run of seen filler lines.
	for i := 0; i < dedupBridgeLines+2; i++ {
		lines.markNew([]byte("filler"))
	}
	var sb strings.Builder
	sb.WriteString("new1\n")
	for i := 0; i < dedupBridgeLines+2; i++ {
		sb.WriteString("filler\n")
	}
	sb.WriteString("new2\n")

	var got []string
	err := emitDedupRuns([]byte(sb.String()), map[string]string{}, lines, func(f Fragment, err error) error {
		got = append(got, f.Raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 runs split by long gap, got %d: %q", len(got), got)
	}
	if got[0] != "new1\n" || got[1] != "new2\n" {
		t.Fatalf("runs = %q, want [new1, new2]", got)
	}
}

func TestLineSeenDedup(t *testing.T) {
	ls := newLineSeen()
	if !ls.markNew([]byte("hello")) {
		t.Fatal("first markNew should be true")
	}
	if ls.markNew([]byte("hello")) {
		t.Fatal("second markNew should be false")
	}
	if !ls.markNew([]byte("world")) {
		t.Fatal("distinct line should be true")
	}
}

func TestBalancedRootQueuesAreStableAndBalanceFamilies(t *testing.T) {
	p := &packFile{objects: []packObject{
		{offset: 10, children: []int32{1, 2, 3, 4}},
		{offset: 11},
		{offset: 12},
		{offset: 13},
		{offset: 14},
		{offset: 20},
		{offset: 30},
	}}
	roots := []int32{0, 5, 6}
	first := balancedRootQueues(p, roots, 2)
	second := balancedRootQueues(p, roots, 2)
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("queue count = %d, want 2", len(first))
	}
	for worker := range first {
		if !slices.Equal(first[worker], second[worker]) {
			t.Fatalf("worker %d assignment is not stable: %v vs %v", worker, first[worker], second[worker])
		}
	}
	if len(first[0]) != 1 || first[0][0] != 0 {
		t.Fatalf("largest family should be isolated first, got %v", first[0])
	}
}
func makeInsertDelta(baseLen int, target []byte) []byte {
	var d []byte
	d = appendDeltaSize(d, baseLen)
	d = appendDeltaSize(d, len(target))
	for off := 0; off < len(target); off += 127 {
		end := off + 127
		if end > len(target) {
			end = len(target)
		}
		d = append(d, byte(end-off))
		d = append(d, target[off:end]...)
	}
	return d
}

func appendDeltaSize(d []byte, n int) []byte {
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			b |= 0x80
		}
		d = append(d, b)
		if n == 0 {
			return d
		}
	}
}

// TestPackScanParity compares pack-scan findings against stock git log -p on a
// bounded commit range of the gitlab repo, asserting every stock secret is
// present in pack output (superset).
func TestPackScanParity(t *testing.T) {
	repo := "/tmp/gitlab.git"
	ctx := context.Background()
	commits, err := listCommits(ctx, repo, "-n 3000 --all")
	if err != nil || len(commits) == 0 {
		t.Skip("gitlab repo not available")
	}

	// stock secrets: added lines from git log -p, keyword-prefiltered set of
	// 40-hex tokens is too rule-specific; instead we just ensure pack scan
	// emits a superset of stock added-line content by substring coverage.
	stockAdds := stockAddedLines(t, ctx, repo, commits)

	packContent := map[string]struct{}{}
	s := &PackScan{RepoPath: repo, LogOpts: "-n 3000 --all", Workers: 4}
	var lines []string
	err = s.Fragments(ctx, func(f Fragment, err error) error {
		if err != nil {
			return err
		}
		for _, ln := range strings.Split(f.Raw, "\n") {
			packContent[strings.TrimSpace(ln)] = struct{}{}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = lines

	missing := 0
	for ln := range stockAdds {
		if _, ok := packContent[ln]; !ok {
			missing++
			if missing <= 10 {
				t.Logf("missing added line: %q", ln)
			}
		}
	}
	if missing > 0 {
		t.Fatalf("pack scan missing %d/%d stock added lines", missing, len(stockAdds))
	}
	t.Logf("stock added lines: %d all covered by pack scan", len(stockAdds))
}

func stockAddedLines(t *testing.T, ctx context.Context, repo string, commits []string) map[string]struct{} {
	t.Helper()
	cmd := exec.CommandContext(ctx, "git", "-C", repo, "log", "-p", "-U0",
		"--stdin", "--no-walk", "--diff-filter=tuxdb")
	cmd.Env = gitConfigIsolationEnv()
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer stdin.Close()
		var b strings.Builder
		for _, c := range commits {
			b.WriteString(c)
			b.WriteByte('\n')
		}
		stdin.Write([]byte(b.String()))
	}()

	adds := map[string]struct{}{}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 1024*1024), 64*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if len(line) > 0 && line[0] == '+' && !strings.HasPrefix(line, "+++") {
			s := strings.TrimSpace(line[1:])
			if s != "" {
				adds[s] = struct{}{}
			}
		}
	}
	cmd.Wait()
	return adds
}

var _ io.Reader
