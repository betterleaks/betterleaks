package sources

// PackScan scans git history by reading packfiles directly instead of asking
// git to compute diffs. Git packs already store most blobs as deltas against a
// similar base; the delta's insert opcodes are exactly the "new" bytes of that
// version. Scanning full (non-delta) blobs plus delta insert regions extended
// to line boundaries covers, by induction, every line of every blob version —
// a strict superset of the added lines that `git log -p` reports — while the
// detector sees only a few percent of the total materialized bytes.
//
// Attribution (commit, path, author) comes from a parallel `git log --raw`
// metadata pass, which is ~40x cheaper than `git log -p` because it never
// computes content diffs. Blobs with no attribution (unreachable, or only
// introduced by merge commits, which stock git log -p also skips) are dropped.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"syscall"

	"github.com/klauspost/compress/zlib"
	"golang.org/x/sync/errgroup"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources/scm"
)

// PackScan is a Source that scans full git history via direct packfile reads.
type PackScan struct {
	RepoPath        string
	ShouldSkip      SkipFunc
	Platform        scm.Platform
	RemoteURL       string
	MaxArchiveDepth int
	// LogOpts selects the commits used for attribution (default --all).
	// The pack scan itself always covers the entire object database.
	LogOpts string
	Workers int
	// FullScanAll disables delta-region optimization and scans every blob's
	// full content. Slower but not subject to pack delta-base artifacts.
	FullScanAll bool
	// Deterministic gives each pack root a fixed worker and private line-set
	// shard. It preserves parallel walking without first-writer-wins ownership.
	Deterministic bool
}

func (s *PackScan) workers() int {
	if s.Workers > 0 {
		return s.Workers
	}
	return runtime.NumCPU()
}

const (
	objCommit   = 1
	objTree     = 2
	objBlob     = 3
	objTag      = 4
	objOfsDelta = 6
	objRefDelta = 7

	// smallBlobFullScan is the size threshold below which a changed blob is
	// scanned in full rather than by line-run dedup. It keeps multiline
	// secrets intact for ordinary source/doc files while still deduping the
	// handful of very large generated blobs that dominate raw byte volume.
	smallBlobFullScan = 1 << 20 // 1 MiB
)

// Fragments implements Source.
func (s *PackScan) Fragments(ctx context.Context, yield FragmentsFunc) error {
	var (
		attrib *blobAttribution
		packs  []*packFile
	)

	// The attribution metadata pass and pack index parsing are independent.
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		var err error
		attrib, err = buildBlobAttribution(gctx, s.RepoPath, s.LogOpts, s.workers())
		return err
	})
	g.Go(func() error {
		var err error
		packs, err = openPacks(s.RepoPath)
		return err
	})
	if err := g.Wait(); err != nil {
		return err
	}
	defer func() {
		for _, p := range packs {
			p.close()
		}
	}()

	total := 0
	for _, p := range packs {
		total += len(p.objects)
	}
	logging.Info().
		Int("packs", len(packs)).
		Int("objects", total).
		Int("attributed_blobs", attrib.len()).
		Int("workers", s.workers()).
		Bool("deterministic", s.Deterministic).
		Msg("pack scan")

	seen := newBlobSeen()
	lineSets := []*lineSeen{newLineSeen()}
	if s.Deterministic {
		lineSets = newLineSeenShards(s.workers(), 1<<25)
	}
	for _, p := range packs {
		if err := s.scanPack(ctx, p, attrib, seen, lineSets, yield); err != nil {
			return err
		}
	}
	return s.scanLooseBlobs(ctx, attrib, seen, lineSets[0], yield)
}

// scanPack walks one pack's delta forest with parallel workers.
func (s *PackScan) scanPack(
	ctx context.Context,
	p *packFile,
	attrib *blobAttribution,
	seen *blobSeen,
	lineSets []*lineSeen,
	yield FragmentsFunc,
) error {
	roots := p.blobRoots()
	if !s.Deterministic {
		return s.scanPackFast(ctx, p, roots, attrib, seen, lineSets[0], yield)
	}
	workerCount := min(s.workers(), len(roots))
	if workerCount == 0 {
		return nil
	}

	queues := balancedRootQueues(p, roots, workerCount)
	g, gctx := errgroup.WithContext(ctx)
	for w := range workerCount {
		lines := lineSets[w]
		queue := queues[w]
		g.Go(func() error {
			walker := newPackWalker(p)
			for _, rootIdx := range queue {
				err := walker.walkFamily(rootIdx, func(idx int32, content []byte) error {
					select {
					case <-gctx.Done():
						return gctx.Err()
					default:
					}
					at, ok := attrib.lookup(p.objects[idx].sha)
					full := !ok || at.fullScan
					return s.emitBlob(gctx, p.objects[idx].sha, content, full, attrib, seen, lines, yield)
				})
				if err != nil {
					return err
				}
			}
			return nil
		})
	}

	return g.Wait()
}

// balancedRootQueues uses delta-family size as a deterministic work estimate.
// Round-robin root ownership is stable but badly imbalanced on real packs:
// one large delta family can strand most workers. Greedy least-loaded
// assignment balances those families while retaining a fixed owner for every
// root. Each queue is restored to physical pack order for locality.
func balancedRootQueues(p *packFile, roots []int32, workers int) [][]int32 {
	type weightedRoot struct {
		idx  int32
		cost uint32
	}
	memo := make([]uint32, len(p.objects))
	var familyCost func(int32) uint32
	familyCost = func(idx int32) uint32 {
		if memo[idx] != 0 {
			return memo[idx]
		}
		cost := uint32(1)
		for _, child := range p.objects[idx].children {
			cost += familyCost(child)
		}
		memo[idx] = cost
		return cost
	}

	weighted := make([]weightedRoot, len(roots))
	for i, root := range roots {
		weighted[i] = weightedRoot{idx: root, cost: familyCost(root)}
	}
	sort.Slice(weighted, func(i, j int) bool {
		if weighted[i].cost != weighted[j].cost {
			return weighted[i].cost > weighted[j].cost
		}
		return p.objects[weighted[i].idx].offset < p.objects[weighted[j].idx].offset
	})

	queues := make([][]int32, workers)
	loads := make([]uint32, workers)
	for _, root := range weighted {
		worker := 0
		for i := 1; i < workers; i++ {
			if loads[i] < loads[worker] {
				worker = i
			}
		}
		queues[worker] = append(queues[worker], root.idx)
		loads[worker] += root.cost
	}
	for _, queue := range queues {
		sort.Slice(queue, func(i, j int) bool {
			return p.objects[queue[i]].offset < p.objects[queue[j]].offset
		})
	}
	return queues
}

// scanPackFast is the original shared-line-set work-stealing implementation.
// It is retained for A/B benchmarking; its first writer wins line ownership.
func (s *PackScan) scanPackFast(
	ctx context.Context,
	p *packFile,
	roots []int32,
	attrib *blobAttribution,
	seen *blobSeen,
	lines *lineSeen,
	yield FragmentsFunc,
) error {
	rootCh := make(chan int32, 256)
	g, gctx := errgroup.WithContext(ctx)
	for range s.workers() {
		g.Go(func() error {
			walker := newPackWalker(p)
			for rootIdx := range rootCh {
				err := walker.walkFamily(rootIdx, func(idx int32, content []byte) error {
					select {
					case <-gctx.Done():
						return gctx.Err()
					default:
					}
					at, ok := attrib.lookup(p.objects[idx].sha)
					full := !ok || at.fullScan
					return s.emitBlob(gctx, p.objects[idx].sha, content, full, attrib, seen, lines, yield)
				})
				if err != nil {
					return err
				}
			}
			return nil
		})
	}
	g.Go(func() error {
		defer close(rootCh)
		for _, rootIdx := range roots {
			select {
			case rootCh <- rootIdx:
			case <-gctx.Done():
				return gctx.Err()
			}
		}
		return nil
	})
	return g.Wait()
}

// emitBlob turns one materialized blob into fragments. Skips unattributed
// blobs and applies path-based skip rules.
//
// Emission strategy:
//   - Binary archives are handed to the File source (which unpacks them).
//   - File adds (and blobs with ambiguous parentage) are scanned whole,
//     matching how stock `git log -p` shows a file add as one full hunk.
//   - Everything else is scanned as maximal runs of globally-unseen lines.
//     By induction every distinct line of every blob version is scanned at
//     least once, so the emitted content is a superset of the added lines
//     stock reports — without depending on how git chose to delta-compress
//     the blob (pack delta-bases are not the logical git parent).
func (s *PackScan) emitBlob(
	ctx context.Context,
	sha [20]byte,
	content []byte,
	fullScan bool,
	attrib *blobAttribution,
	seen *blobSeen,
	lines *lineSeen,
	yield FragmentsFunc,
) error {
	if len(content) == 0 || !seen.first(sha) {
		return nil
	}
	at, ok := attrib.lookup(sha)
	if !ok {
		return nil
	}

	attrs := map[string]string{
		AttrGitSHA:         at.commit.sha,
		AttrResource:       ResourceGitPatchContent,
		AttrPath:           at.path,
		AttrGitMessage:     at.commit.message,
		AttrGitAuthorName:  at.commit.author,
		AttrGitAuthorEmail: at.commit.email,
		AttrGitDate:        at.commit.date,
	}
	if s.RemoteURL != "" {
		attrs[AttrGitRemoteURL] = s.RemoteURL
		attrs[AttrGitPlatform] = s.Platform.String()
	}
	if shouldSkipAttrs(s.ShouldSkip, attrs) {
		return nil
	}

	if isBinaryBlob(content) {
		if !isArchive(ctx, at.path) {
			return nil
		}
		file := File{
			Content:         bytes.NewReader(content),
			Path:            at.path,
			MaxArchiveDepth: s.MaxArchiveDepth,
			ShouldSkip:      s.ShouldSkip,
		}
		return file.Fragments(ctx, func(fragment Fragment, err error) error {
			for k, v := range attrs {
				if fragment.Attr(k) == "" {
					fragment.SetAttr(k, v)
				}
			}
			return yield(fragment, err)
		})
	}

	if fullScan || s.FullScanAll {
		lines.markAll(content)
		return emitFullContent(content, attrs, yield)
	}
	return emitDedupRuns(content, attrs, lines, yield)
}

// emitFullContent yields an entire blob as one fragment, mirroring how stock
// git log -p presents a file add as a single hunk.
func emitFullContent(content []byte, attrs map[string]string, yield FragmentsFunc) error {
	frag := Fragment{
		Raw:        string(content),
		StartLine:  1,
		Attributes: attrs,
	}
	return yield(frag, nil)
}

// dedupBridgeLines controls how many consecutive already-seen lines may be
// swallowed into a run before it is flushed. Bridging keeps multiline secrets
// intact when a common interior line (a blank line, a "-----BEGIN..." marker,
// a repeated boilerplate line) was already seen elsewhere, and it also cuts the
// number of fragments handed to the detector.
const dedupBridgeLines = 12

// emitDedupRuns yields runs of lines that include at least one line not seen
// anywhere in the corpus so far, bridging short spans of already-seen lines so
// multiline secrets stay contiguous. Line numbers are relative to the blob and
// match how stock groups added lines into hunks.
func emitDedupRuns(content []byte, attrs map[string]string, lines *lineSeen, yield FragmentsFunc) error {
	lineNo := 1
	runStart := -1 // byte offset where the current run begins
	runStartLine := 0
	runEnd := 0  // byte offset just past the last confirmed-new line
	seenGap := 0 // consecutive already-seen lines since the last new line

	flush := func() error {
		if runStart < 0 {
			return nil
		}
		frag := Fragment{
			Raw:        string(content[runStart:runEnd]),
			StartLine:  runStartLine,
			Attributes: attrs,
		}
		runStart = -1
		seenGap = 0
		return yield(frag, nil)
	}

	lineStart := 0
	for i := 0; i <= len(content); i++ {
		if i < len(content) && content[i] != '\n' {
			continue
		}
		lineEnd := i
		if i < len(content) {
			lineEnd = i + 1 // include newline
		}
		if lines.markNew(content[lineStart:i]) {
			if runStart < 0 {
				runStart = lineStart
				runStartLine = lineNo
			}
			runEnd = lineEnd
			seenGap = 0
		} else if runStart >= 0 {
			seenGap++
			if seenGap > dedupBridgeLines {
				if err := flush(); err != nil {
					return err
				}
			}
		}
		lineStart = i + 1
		lineNo++
	}
	return flush()
}

func isBinaryBlob(content []byte) bool {
	n := len(content)
	if n > 8000 {
		n = 8000
	}
	return bytes.IndexByte(content[:n], 0) >= 0
}

// --- pack file parsing ---

type packObject struct {
	offset  int64
	sha     [20]byte
	typ     byte
	baseOff int64 // -1 unless delta
	// children are indexes of objects whose delta base is this object.
	children []int32
}

type packFile struct {
	path    string
	data    []byte // mmap
	objects []packObject
	// byOffset sorts object indexes by pack offset (for ref-delta and roots).
	offToIdx map[int64]int32
}

func (p *packFile) close() {
	if p.data != nil {
		_ = syscall.Munmap(p.data)
		p.data = nil
	}
}

// blobRoots returns indexes of non-delta blob objects (delta family roots).
// Delta chains never mix types, so a blob family always has a blob root.
func (p *packFile) blobRoots() []int32 {
	var roots []int32
	for i := range p.objects {
		if p.objects[i].baseOff < 0 && p.objects[i].typ == objBlob {
			roots = append(roots, int32(i))
		}
	}
	return roots
}

func openPacks(repoPath string) ([]*packFile, error) {
	gitDir := repoPath
	if fi, err := os.Stat(filepath.Join(repoPath, ".git")); err == nil && fi.IsDir() {
		gitDir = filepath.Join(repoPath, ".git")
	}
	paths, err := filepath.Glob(filepath.Join(gitDir, "objects", "pack", "*.pack"))
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no packfiles found under %s", gitDir)
	}
	var packs []*packFile
	for _, path := range paths {
		p, err := openPack(path)
		if err != nil {
			for _, q := range packs {
				q.close()
			}
			return nil, fmt.Errorf("open pack %s: %w", path, err)
		}
		packs = append(packs, p)
	}
	return packs, nil
}

func openPack(path string) (*packFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	data, err := syscall.Mmap(int(f.Fd()), 0, int(st.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, err
	}
	if len(data) < 12 || string(data[:4]) != "PACK" {
		syscall.Munmap(data)
		return nil, fmt.Errorf("bad pack header")
	}

	entries, err := readIdx(path[:len(path)-5] + ".idx")
	if err != nil {
		syscall.Munmap(data)
		return nil, err
	}

	p := &packFile{
		path:     path,
		data:     data,
		objects:  make([]packObject, len(entries)),
		offToIdx: make(map[int64]int32, len(entries)),
	}
	for i, e := range entries {
		p.objects[i] = packObject{offset: e.offset, sha: e.sha, baseOff: -1}
		p.offToIdx[e.offset] = int32(i)
	}

	// Parse each object header to determine type and delta base.
	shaToIdx := make(map[[20]byte]int32, len(entries))
	for i := range p.objects {
		shaToIdx[p.objects[i].sha] = int32(i)
	}
	for i := range p.objects {
		typ, _, baseRel, refSha, _ := parsePackHeader(data, p.objects[i].offset)
		p.objects[i].typ = typ
		switch typ {
		case objOfsDelta:
			p.objects[i].baseOff = p.objects[i].offset - baseRel
		case objRefDelta:
			base, ok := shaToIdx[refSha]
			if !ok {
				syscall.Munmap(data)
				return nil, fmt.Errorf("ref-delta base %x not in pack", refSha)
			}
			p.objects[i].baseOff = p.objects[base].offset
		}
	}
	// Build children lists and propagate root type through delta chains.
	for i := range p.objects {
		if p.objects[i].baseOff >= 0 {
			parent, ok := p.offToIdx[p.objects[i].baseOff]
			if !ok {
				syscall.Munmap(data)
				return nil, fmt.Errorf("delta base offset %d not found", p.objects[i].baseOff)
			}
			p.objects[parent].children = append(p.objects[parent].children, int32(i))
		}
	}
	return p, nil
}

type idxEntry struct {
	sha    [20]byte
	offset int64
}

func readIdx(path string) ([]idxEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 8+256*4 || binary.BigEndian.Uint32(data[0:4]) != 0xff744f63 {
		return nil, fmt.Errorf("unsupported idx format (need v2)")
	}
	if v := binary.BigEndian.Uint32(data[4:8]); v != 2 {
		return nil, fmt.Errorf("unsupported idx version %d", v)
	}
	n := int(binary.BigEndian.Uint32(data[8+255*4 : 8+256*4]))
	shaBase := 8 + 256*4
	crcBase := shaBase + n*20
	offBase := crcBase + n*4
	largeBase := offBase + n*4

	entries := make([]idxEntry, n)
	for i := 0; i < n; i++ {
		copy(entries[i].sha[:], data[shaBase+i*20:shaBase+i*20+20])
		v := binary.BigEndian.Uint32(data[offBase+i*4 : offBase+i*4+4])
		if v&0x80000000 != 0 {
			li := int(v & 0x7fffffff)
			entries[i].offset = int64(binary.BigEndian.Uint64(data[largeBase+li*8 : largeBase+li*8+8]))
		} else {
			entries[i].offset = int64(v)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].offset < entries[j].offset })
	return entries, nil
}

// parsePackHeader parses the object header at off. Returns the object type,
// inflated size, relative base offset (ofs-delta), base sha (ref-delta), and
// the offset where the zlib data begins.
func parsePackHeader(data []byte, off int64) (typ byte, size int64, baseRel int64, refSha [20]byte, dataStart int64) {
	p := off
	b := data[p]
	p++
	typ = b >> 4 & 7
	size = int64(b & 15)
	shift := uint(4)
	for b&0x80 != 0 {
		b = data[p]
		p++
		size |= int64(b&0x7f) << shift
		shift += 7
	}
	switch typ {
	case objOfsDelta:
		b = data[p]
		p++
		baseRel = int64(b & 0x7f)
		for b&0x80 != 0 {
			b = data[p]
			p++
			baseRel = (baseRel+1)<<7 | int64(b&0x7f)
		}
	case objRefDelta:
		copy(refSha[:], data[p:p+20])
		p += 20
	}
	return typ, size, baseRel, refSha, p
}

// --- delta forest walking ---

type packWalker struct {
	p  *packFile
	zr io.ReadCloser
	br *bytes.Reader
	// depthBufs[d] is a reusable materialization buffer for DFS depth d.
	// A frame's content is only alive while its subtree is being walked, so
	// the next sibling at the same depth can safely overwrite it. This keeps
	// the 100s-of-GB materialization volume out of the garbage collector.
	depthBufs [][]byte
	deltaBuf  []byte
}

func newPackWalker(p *packFile) *packWalker {
	return &packWalker{p: p, br: bytes.NewReader(nil)}
}

func (w *packWalker) bufForDepth(depth int, size int64) []byte {
	for len(w.depthBufs) <= depth {
		w.depthBufs = append(w.depthBufs, nil)
	}
	if int64(cap(w.depthBufs[depth])) < size {
		w.depthBufs[depth] = make([]byte, size)
	}
	return w.depthBufs[depth][:size]
}

// inflate decompresses the object data at dataStart into out (len == size).
func (w *packWalker) inflate(dataStart int64, out []byte) error {
	w.br.Reset(w.p.data[dataStart:])
	if w.zr == nil {
		zr, err := zlib.NewReader(w.br)
		if err != nil {
			return err
		}
		w.zr = zr
	} else if err := w.zr.(zlib.Resetter).Reset(w.br, nil); err != nil {
		return err
	}
	_, err := io.ReadFull(w.zr, out)
	return err
}

// walkFamily materializes a delta family rooted at rootIdx (a non-delta blob)
// depth-first, calling fn for each blob: root gets regions == nil (scan all),
// deltas get their extended insert regions.
type walkFrame struct {
	idx     int32
	content []byte
	child   int
}

func (w *packWalker) walkFamily(rootIdx int32, fn func(idx int32, content []byte) error) error {
	root := &w.p.objects[rootIdx]
	_, size, _, _, dataStart := parsePackHeader(w.p.data, root.offset)
	content := w.bufForDepth(0, size)
	if err := w.inflate(dataStart, content); err != nil {
		return fmt.Errorf("inflate root %x: %w", root.sha, err)
	}
	if err := fn(rootIdx, content); err != nil {
		return err
	}

	stack := []walkFrame{{idx: rootIdx, content: content}}
	for len(stack) > 0 {
		f := &stack[len(stack)-1]
		obj := &w.p.objects[f.idx]
		if f.child >= len(obj.children) {
			stack[len(stack)-1].content = nil
			stack = stack[:len(stack)-1]
			continue
		}
		childIdx := obj.children[f.child]
		f.child++
		depth := len(stack)

		child := &w.p.objects[childIdx]
		_, dsize, _, _, cStart := parsePackHeader(w.p.data, child.offset)
		if int64(cap(w.deltaBuf)) < dsize {
			w.deltaBuf = make([]byte, dsize)
		}
		delta := w.deltaBuf[:dsize]
		if err := w.inflate(cStart, delta); err != nil {
			return fmt.Errorf("inflate delta %x: %w", child.sha, err)
		}
		tgtSize, hdrLen, err := deltaTargetSize(delta)
		if err != nil {
			return fmt.Errorf("delta header %x: %w", child.sha, err)
		}
		target := w.bufForDepth(depth, tgtSize)
		if err := applyDelta(f.content, delta[hdrLen:], target); err != nil {
			return fmt.Errorf("apply delta %x: %w", child.sha, err)
		}
		if err := fn(childIdx, target); err != nil {
			return err
		}
		stack = append(stack, walkFrame{idx: childIdx, content: target})
	}
	return nil
}

// deltaTargetSize parses the two size varints at the head of a delta payload
// and returns the target size and header length.
func deltaTargetSize(delta []byte) (int64, int, error) {
	pos := 0
	for pos < len(delta) && delta[pos]&0x80 != 0 {
		pos++
	}
	pos++
	tgtSize := int64(0)
	shift := uint(0)
	for pos < len(delta) {
		c := delta[pos]
		pos++
		tgtSize |= int64(c&0x7f) << shift
		shift += 7
		if c&0x80 == 0 {
			return tgtSize, pos, nil
		}
	}
	return 0, 0, fmt.Errorf("truncated delta header")
}

// applyDelta applies git delta opcodes (header already stripped) to base,
// writing the reconstructed object into target (pre-sized to the delta's
// target size).
func applyDelta(base, ops []byte, target []byte) error {
	pos := 0
	out := 0
	for pos < len(ops) {
		op := ops[pos]
		pos++
		if op&0x80 != 0 { // copy from base
			var cpOff, cpLen int64
			for bit := 0; bit < 4; bit++ {
				if op&(1<<bit) != 0 {
					cpOff |= int64(ops[pos]) << (8 * bit)
					pos++
				}
			}
			for bit := 0; bit < 3; bit++ {
				if op&(0x10<<bit) != 0 {
					cpLen |= int64(ops[pos]) << (8 * bit)
					pos++
				}
			}
			if cpLen == 0 {
				cpLen = 0x10000
			}
			if cpOff+cpLen > int64(len(base)) || out+int(cpLen) > len(target) {
				return fmt.Errorf("delta copy out of range")
			}
			copy(target[out:], base[cpOff:cpOff+cpLen])
			out += int(cpLen)
		} else if op != 0 { // insert literal
			if pos+int(op) > len(ops) || out+int(op) > len(target) {
				return fmt.Errorf("delta insert out of range")
			}
			copy(target[out:], ops[pos:pos+int(op)])
			out += int(op)
			pos += int(op)
		} else {
			return fmt.Errorf("reserved delta opcode 0")
		}
	}
	if out != len(target) {
		return fmt.Errorf("delta target size mismatch")
	}
	return nil
}

// --- loose objects ---

// scanLooseBlobs handles blobs stored outside packs (uncommon on fresh
// clones, normal on long-lived repos).
func (s *PackScan) scanLooseBlobs(
	ctx context.Context,
	attrib *blobAttribution,
	seen *blobSeen,
	lines *lineSeen,
	yield FragmentsFunc,
) error {
	gitDir := s.RepoPath
	if fi, err := os.Stat(filepath.Join(s.RepoPath, ".git")); err == nil && fi.IsDir() {
		gitDir = filepath.Join(s.RepoPath, ".git")
	}
	objDir := filepath.Join(gitDir, "objects")
	count := 0
	for hi := 0; hi < 256; hi++ {
		dir := filepath.Join(objDir, fmt.Sprintf("%02x", hi))
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			name := ent.Name()
			if len(name) != 38 {
				continue
			}
			var sha [20]byte
			if _, err := hex.Decode(sha[:], []byte(fmt.Sprintf("%02x%s", hi, name))); err != nil {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				continue
			}
			zr, err := zlib.NewReader(bytes.NewReader(raw))
			if err != nil {
				continue
			}
			obj, err := io.ReadAll(zr)
			zr.Close()
			if err != nil {
				continue
			}
			nul := bytes.IndexByte(obj, 0)
			if nul < 0 || !bytes.HasPrefix(obj, []byte("blob ")) {
				continue
			}
			count++
			at, ok := attrib.lookup(sha)
			full := !ok || at.fullScan
			if err := s.emitBlob(ctx, sha, obj[nul+1:], full, attrib, seen, lines, yield); err != nil {
				return err
			}
		}
	}
	if count > 0 {
		logging.Debug().Int("loose_blobs", count).Msg("pack scan: scanned loose blobs")
	}
	return nil
}
