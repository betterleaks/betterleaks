package sources

// Blob attribution for PackScan: maps every blob to the earliest commit that
// introduced it (per `git log --raw`, which reports new-blob hashes without
// computing content diffs).

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
)

type blobCommit struct {
	sha     string
	author  string
	email   string
	date    string // RFC3339
	message string
	// order is the commit's position in rev-list output (0 = newest). Used to
	// pick the oldest introduction when a blob appears in many commits.
	order int
}

type blobAttrEntry struct {
	commit *blobCommit
	path   string
	// status is the git change status letter (A, M, C, R, ...) of the change
	// that introduced this blob.
	status byte
	// fullScan is set when this blob must be scanned in full rather than by
	// delta regions: file adds (A/C/R), blobs with more than one distinct
	// git parent, or (decided later) blobs whose pack delta-base differs from
	// their git parent.
	fullScan bool
	// parent is the git-parent blob sha (old sha) for the single-parent
	// modify case; used to check whether the pack delta-base matches the
	// logical parent so region scanning is exact.
	parent    [20]byte
	hasParent bool
}

type blobAttribution struct {
	mu sync.Mutex
	m  map[[20]byte]blobAttrEntry
}

func (a *blobAttribution) len() int { return len(a.m) }

func (a *blobAttribution) lookup(sha [20]byte) (blobAttrEntry, bool) {
	e, ok := a.m[sha]
	return e, ok
}

// add keeps the entry from the oldest commit (highest rev-list order) and
// accumulates the fullScan bit across all introductions. A blob seen with two
// distinct git parents must be full-scanned (region scan is only exact for a
// single, known parent).
func (a *blobAttribution) add(sha [20]byte, e blobAttrEntry) {
	e.fullScan = e.status == 'A' || e.status == 'C' || e.status == 'R'
	a.mu.Lock()
	prev, ok := a.m[sha]
	if !ok {
		a.m[sha] = e
		a.mu.Unlock()
		return
	}
	// Distinct parents across introductions -> force full scan.
	forceFull := prev.fullScan || e.fullScan
	if prev.hasParent && e.hasParent && prev.parent != e.parent {
		forceFull = true
	}
	if e.commit.order > prev.commit.order {
		e.fullScan = forceFull
		a.m[sha] = e
	} else {
		prev.fullScan = forceFull
		a.m[sha] = prev
	}
	a.mu.Unlock()
}

// buildBlobAttribution runs parallel `git log --raw` workers over all commits
// and returns newBlobHash -> (introducing commit, path).
func buildBlobAttribution(ctx context.Context, repoPath, logOpts string, workers int) (*blobAttribution, error) {
	commits, err := listCommits(ctx, repoPath, logOpts)
	if err != nil {
		return nil, fmt.Errorf("list commits: %w", err)
	}
	attrib := &blobAttribution{m: make(map[[20]byte]blobAttrEntry, len(commits)*2)}
	if len(commits) == 0 {
		return attrib, nil
	}
	if workers > len(commits) {
		workers = len(commits)
	}
	chunk := (len(commits) + workers - 1) / workers

	g, gctx := errgroup.WithContext(ctx)
	for i := 0; i < workers; i++ {
		start := i * chunk
		if start >= len(commits) {
			break
		}
		end := start + chunk
		if end > len(commits) {
			end = len(commits)
		}
		part := commits[start:end]
		orderBase := start
		g.Go(func() error {
			return attributionWorker(gctx, repoPath, part, orderBase, attrib)
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return attrib, nil
}

func attributionWorker(ctx context.Context, repoPath string, commits []string, orderBase int, attrib *blobAttribution) error {
	cmd := exec.CommandContext(ctx, "git", "-C", repoPath,
		"log", "--stdin", "--no-walk",
		"--format=C%x1e%H%x1e%an%x1e%ae%x1e%at%x1e%s",
		"--raw", "--no-abbrev", "--diff-filter=tuxdb")
	cmd.Env = gitConfigIsolationEnv()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	go func() {
		defer stdin.Close()
		var b strings.Builder
		for _, sha := range commits {
			b.WriteString(sha)
			b.WriteByte('\n')
		}
		io.WriteString(stdin, b.String())
	}()

	var (
		cur   *blobCommit
		order = orderBase - 1
		sc    = bufio.NewScanner(stdout)
	)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "C\x1e") {
			parts := strings.Split(line, "\x1e")
			if len(parts) < 6 {
				return fmt.Errorf("bad commit line %q", line)
			}
			order++
			date := ""
			if ts, err := strconv.ParseInt(parts[4], 10, 64); err == nil {
				date = time.Unix(ts, 0).UTC().Format(time.RFC3339)
			}
			cur = &blobCommit{
				sha:     parts[1],
				author:  parts[2],
				email:   parts[3],
				date:    date,
				message: parts[5],
				order:   order,
			}
			continue
		}
		if len(line) == 0 || line[0] != ':' || cur == nil {
			continue
		}
		// :100644 100644 <old-sha> <new-sha> <status>\t<path>[\t<newpath>]
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			continue
		}
		fields := strings.Fields(line[1:tab])
		if len(fields) < 5 || fields[4] == "" || fields[4][0] == 'D' {
			continue
		}
		newSha := fields[3]
		if len(newSha) != 40 || strings.HasPrefix(newSha, "0000000") {
			continue
		}
		var sha [20]byte
		if _, err := hex.Decode(sha[:], []byte(newSha)); err != nil {
			continue
		}
		entry := blobAttrEntry{commit: cur, path: strings.Split(line[tab+1:], "\t")[len(strings.Split(line[tab+1:], "\t"))-1], status: fields[4][0]}
		if oldSha := fields[2]; len(oldSha) == 40 && !strings.HasPrefix(oldSha, "0000000") {
			if _, err := hex.Decode(entry.parent[:], []byte(oldSha)); err == nil {
				entry.hasParent = true
			}
		}
		attrib.add(sha, entry)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return cmd.Wait()
}

// blobSeen dedups blobs across packs and loose objects (a blob can exist in
// multiple packs).
type blobSeen struct {
	mu sync.Mutex
	m  map[[20]byte]struct{}
}

func newBlobSeen() *blobSeen {
	return &blobSeen{m: make(map[[20]byte]struct{}, 1<<20)}
}

// first returns true exactly once per sha.
func (s *blobSeen) first(sha [20]byte) bool {
	s.mu.Lock()
	_, ok := s.m[sha]
	if !ok {
		s.m[sha] = struct{}{}
	}
	s.mu.Unlock()
	return !ok
}

// lineSeen is a lock-free concurrent set of 64-bit line-content fingerprints.
// It lets the pack scan emit each distinct line of history to the detector
// roughly once, collapsing the ~180 GB of materialized blob content down to the
// few GB of genuinely unique lines. The set is a fixed open-addressing table
// with atomic linear probing, which avoids the mutex/map overhead that
// otherwise dominates when checking the ~10^9 lines materialized from a pack.
//
// Fingerprint collisions (which would silently skip a line) are vanishingly
// rare and only ever cause a superset scan to omit a duplicate of
// already-scanned content, so they are acceptable for this best-effort dedup.
type lineSeen struct {
	slots []uint64
	mask  uint64
}

// newLineSeenSized builds a table with capacity for ~n entries (rounded up to a
// power of two at ~2x for a low load factor).
func newLineSeenSized(n int) *lineSeen {
	size := uint64(1) << 20
	target := uint64(n) * 2
	for size < target {
		size <<= 1
	}
	return &lineSeen{slots: make([]uint64, size), mask: size - 1}
}

func newLineSeen() *lineSeen { return newLineSeenSized(1 << 25) }

// markNew records the line's fingerprint and returns true if it was not already
// present.
func (ls *lineSeen) markNew(line []byte) bool {
	return ls.mark(hashLine(line))
}

// has reports whether the fingerprint is already present, without inserting it.
func (ls *lineSeen) has(h uint64) bool {
	idx := h & ls.mask
	for {
		cur := atomic.LoadUint64(&ls.slots[idx])
		if cur == h {
			return true
		}
		if cur == 0 {
			return false
		}
		idx = (idx + 1) & ls.mask
	}
}

// mark inserts the fingerprint and returns true if it was newly added.
func (ls *lineSeen) mark(h uint64) bool {
	idx := h & ls.mask
	for {
		cur := atomic.LoadUint64(&ls.slots[idx])
		if cur == h {
			return false
		}
		if cur == 0 {
			if atomic.CompareAndSwapUint64(&ls.slots[idx], 0, h) {
				return true
			}
			continue // lost the race for this slot; re-read it
		}
		idx = (idx + 1) & ls.mask
	}
}

// anyNew reports whether content contains at least one line not yet seen,
// without recording anything.
func (ls *lineSeen) anyNew(content []byte) bool {
	start := 0
	for i := 0; i <= len(content); i++ {
		if i < len(content) && content[i] != '\n' {
			continue
		}
		if !ls.has(hashLine(content[start:i])) {
			return true
		}
		start = i + 1
	}
	return false
}

// markAll records every line of content as seen (used for fully-scanned blobs
// so later modifications don't re-emit their unchanged lines).
func (ls *lineSeen) markAll(content []byte) {
	start := 0
	for i := 0; i <= len(content); i++ {
		if i < len(content) && content[i] != '\n' {
			continue
		}
		ls.markNew(content[start:i])
		start = i + 1
	}
}

// hashLine is a fast 64-bit fingerprint of a line, processing eight bytes per
// multiply to keep up with the ~10^9 lines materialized from a large pack. It
// is avalanche-mixed and forced non-zero (0 is the empty-slot sentinel).
func hashLine(b []byte) uint64 {
	const (
		prime = 1099511628211
		seed  = 1469598103934665603
	)
	h := uint64(seed)
	i := 0
	for ; i+8 <= len(b); i += 8 {
		h ^= binary.LittleEndian.Uint64(b[i:])
		h *= prime
	}
	if i < len(b) {
		var last uint64
		for j := i; j < len(b); j++ {
			last = last<<8 | uint64(b[j])
		}
		h ^= last
		h *= prime
	}
	h ^= uint64(len(b))
	h ^= h >> 29
	h *= prime
	h ^= h >> 32
	if h == 0 {
		h = 1
	}
	return h
}
