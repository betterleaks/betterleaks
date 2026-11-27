package gogit

import (
	"context"
	"errors"
	"hash/maphash"
	"strings"
	"unicode/utf8"

	"github.com/betterleaks/betterleaks/v2/internal/gitobj"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/filesystem"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/mholt/archives"
)

func (w *worker) change(ctx context.Context, c *gitobj.Change, attrs map[string]string, yield sources.FragmentsFunc) error {
	emit := func(raw string, line int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return yield(sources.Fragment{Raw: raw, StartLine: line, Attributes: attrs}, nil)
	}
	kindChanged := c.From.Name != "" && uint32(c.From.TreeEntry.Mode)&0170000 != uint32(c.To.TreeEntry.Mode)&0170000
	if c.From.Name != "" && c.From.TreeEntry.Hash == c.To.TreeEntry.Hash && !kindChanged {
		return nil
	}
	cacheable := c.From.Name != "" && !kindChanged && c.From.TreeEntry.Mode != filemode.Submodule && c.To.TreeEntry.Mode != filemode.Submodule
	key := patchKey{c.From.TreeEntry.Hash, c.To.TreeEntry.Hash}
	if cacheable {
		if additions, ok := w.patches.get(key); ok {
			for _, a := range additions {
				if err := ctx.Err(); err != nil {
					return err
				}
				if err := emit(a.raw, a.line); err != nil {
					return err
				}
			}
			return ctx.Err()
		}
	}
	dst, binary, err := w.content(ctx, c.To)
	if err != nil {
		return err
	}
	if binary {
		return w.archive(ctx, c.To.Name, dst, attrs, yield)
	}
	if c.From.Name == "" || kindChanged {
		return emit(dst, 1)
	}
	src, binary, err := w.content(ctx, c.From)
	if err != nil {
		return err
	}
	if binary {
		// Nothing in a binary predecessor matches a text line.
		return emit(dst, 1)
	}
	if !cacheable {
		return w.differ.additions(ctx, src, dst, emit)
	}
	var additions []textAddition
	size := patchOverhead
	err = w.differ.additions(ctx, src, dst, func(raw string, line int) error {
		if err := emit(raw, line); err != nil {
			return err
		}
		if size <= maxCachedPatch {
			size += len(raw) + 24
			if size <= maxCachedPatch {
				additions = append(additions, textAddition{raw, line})
			} else {
				additions = nil
			}
		}
		return nil
	})
	if err == nil && size <= maxCachedPatch {
		w.patches.put(key, additions)
	}
	return err
}

// Each worker reuses its line bookkeeping, but releases unusually large diffs
// and clears dictionary keys so scratch space never keeps old blobs alive.
type lineDiffer struct {
	lines        lineTable
	old, current []rune
	positions    []int
	starts       []int // destination line offsets
	inOld, inNew []int32
	classes      []byte
	search       editSearch
}

func resize[T any](s []T, n int) []T {
	if cap(s) < n {
		return make([]T, n)
	}
	return s[:n]
}

// Like Git's xdiff, trim the lines both versions share at either end, then
// leave lines that cannot be matches out of the quadratic edit search and map
// matching destination lines back to their original positions. Most changes
// touch a few lines of a large file, and generated files can replace tens of
// thousands of lines; diffing unmatched lines wastes almost all CPU time.
// As with Git's own preprocessing, ambiguous edit boundaries can differ from
// an unpruned diff. We preserve exact destination contents and line numbers.
func (d *lineDiffer) additions(ctx context.Context, src, dst string, emit func(string, int) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Preprocessing runs before the edit search's timeout. Poll cancellation
	// in batches, including pruning where each line can inspect 200 neighbors.
	const checkEvery = 256
	// Each end must stop at a line boundary: appending bytes to an unterminated
	// final line replaces that line instead of introducing a new one.
	whole := dst
	prefix := commonLinePrefix(src, dst)
	base := strings.Count(dst[:prefix], "\n")
	src, dst = src[prefix:], dst[prefix:]
	suffix := commonLineSuffix(src, dst)
	src, dst = src[:len(src)-suffix], dst[:len(dst)-suffix]
	add := func(raw string, line int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Clone parts so a small queued addition cannot keep a large blob alive.
		if len(raw) < len(whole) {
			raw = strings.Clone(raw)
		}
		return emit(raw, base+line)
	}
	if dst == "" {
		return nil
	}
	if src == "" {
		return add(dst, 1)
	}
	// Bound the bookkeeping allocated for a diff independently of its input
	// byte limit. Larger changes are scanned whole, which can only add findings.
	oldBreaks, newBreaks := strings.Count(src, "\n"), strings.Count(dst, "\n")
	if oldBreaks+newBreaks+2 > maxDiffLines {
		return add(dst, 1)
	}
	// Tokenize parent lines once; destination-only lines need neither IDs nor
	// strings in the dictionary.
	lineCount := func(text string, n int) int {
		if len(text) > 0 && text[len(text)-1] != '\n' {
			n++
		}
		return n
	}
	oldCount, newCount := lineCount(src, oldBreaks), lineCount(dst, newBreaks)
	if oldCount == 1 && newCount == 1 {
		// Identical lines were removed by the prefix/suffix trim.
		return add(dst, 1)
	}
	lines := &d.lines
	lines.reset(oldCount)
	defer func() {
		lines.release()
		if oldCount > 65536 || newCount > 65536 {
			*d = lineDiffer{} //nolint:exhaustruct // Drop every retained buffer after a large diff.
		}
	}()
	d.classes = resize(d.classes, oldCount+newCount)
	oldClasses, newClasses := d.classes[:oldCount], d.classes[oldCount:]
	d.old = resize(d.old, oldCount)
	a := d.old[:0]
	for offset := 0; offset < len(src); {
		if len(a)%checkEvery == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		end := strings.IndexByte(src[offset:], '\n')
		if end < 0 {
			end = len(src)
		} else {
			end += offset + 1
		}
		line := src[offset:end]
		id := lines.insert(line)
		oldClasses[len(a)] = blankFlag(line)
		a = append(a, id)
		offset = end
	}
	// Count every line in both versions. Destination-only lines get ID 0.
	d.inOld, d.inNew = resize(d.inOld, lines.count+1), resize(d.inNew, lines.count+1)
	inOld, inNew := d.inOld, d.inNew
	clear(inOld)
	clear(inNew)
	for _, id := range a {
		inOld[id]++
	}
	d.current = resize(d.current, newCount)
	d.starts = resize(d.starts, newCount)
	b, starts := d.current, d.starts
	for offset, pos := 0, 0; offset < len(dst); pos++ {
		if pos%checkEvery == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		end := strings.IndexByte(dst[offset:], '\n')
		if end < 0 {
			end = len(dst)
		} else {
			end += offset + 1
		}
		starts[pos] = offset
		b[pos] = lines.find(dst[offset:end])
		inNew[b[pos]]++
		newClasses[pos] = blankFlag(dst[offset:end])
		offset = end
	}
	classifyLines(oldClasses, a, inNew)
	classifyLines(newClasses, b, inOld)
	old := a[:0]
	for i, id := range a {
		if i%checkEvery == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if searchable(oldClasses, i) {
			old = append(old, id)
		}
	}
	current := b[:0]
	d.positions = resize(d.positions, newCount)
	positions := d.positions[:0]
	for pos, id := range b {
		if pos%checkEvery == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if searchable(newClasses, pos) {
			current = append(current, id)
			positions = append(positions, pos)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(current) == 0 {
		return add(dst, 1)
	}
	edits, complete := d.search.diff(ctx, old, current, diffTimeout)
	if err := ctx.Err(); err != nil {
		return err
	}
	if !complete {
		return add(dst, 1)
	}
	// Emit gaps between matched destination lines directly. Pruned lines in
	// those gaps belong to the same addition as explicit insertions.
	at, next := 0, 0
	for _, e := range edits {
		switch e.op {
		case editEqual:
			for _, pos := range positions[at : at+e.n] {
				if next < pos {
					if err := add(dst[starts[next]:starts[pos]], next+1); err != nil {
						return err
					}
				}
				next = pos + 1
			}
			at += e.n
		case editInsert:
			at += e.n
		}
	}
	if next < newCount {
		return add(dst[starts[next]:], next+1)
	}
	return ctx.Err()
}

// lineTable assigns dense IDs to distinct parent lines in first-seen order.
// Each slot packs the upper half of a line's hash with its ID, so probes touch
// eight bytes and compare text only for a likely match. Lines are kept by ID,
// which destination lookups visit in nearly parent order. Slots are reused
// across diffs, and release clears the used ones and the lines so scratch
// space never keeps an old blob alive.
type lineTable struct {
	slots []uint64 // hash tag | ID; zero is free because IDs start at one
	lines []string // by ID
	used  []int32  // slot index by ID
	mask  int
	count int
}

const lineTagMask = uint64(0xffffffff) << 32

var lineSeed = maphash.MakeSeed()

// reset prepares for at most n distinct lines at a load factor of one half.
func (t *lineTable) reset(n int) {
	size := 16
	for size < 2*n {
		size <<= 1
	}
	if len(t.slots) < size {
		t.slots = make([]uint64, size)
	}
	t.mask = len(t.slots) - 1
	t.count = 0
	t.lines = append(t.lines[:0], "")
	t.used = append(t.used[:0], 0)
}

func (t *lineTable) release() {
	t.count = 0
	if len(t.slots) > 1<<18 {
		// Retain only tables of moderate size between diffs.
		*t = lineTable{} //nolint:exhaustruct // Drop every buffer.
		return
	}
	for _, i := range t.used[1:] {
		t.slots[i] = 0
	}
	clear(t.lines)
	t.lines, t.used = t.lines[:0], t.used[:0]
}

// insert returns line's ID, assigning the next one to a new line.
func (t *lineTable) insert(line string) rune {
	h := maphash.String(lineSeed, line)
	tag := h & lineTagMask
	for i := int(h) & t.mask; ; i = (i + 1) & t.mask {
		s := t.slots[i]
		if s == 0 {
			t.count++
			t.slots[i] = tag | uint64(t.count)
			t.lines = append(t.lines, line)
			t.used = append(t.used, int32(i))
			return rune(t.count)
		}
		if s&lineTagMask == tag && t.lines[uint32(s)] == line {
			return rune(uint32(s))
		}
	}
}

// find returns line's ID, or zero for a line the parent does not contain.
func (t *lineTable) find(line string) rune {
	if len(t.slots) == 0 {
		return 0
	}
	h := maphash.String(lineSeed, line)
	tag := h & lineTagMask
	for i := int(h) & t.mask; ; i = (i + 1) & t.mask {
		s := t.slots[i]
		if s == 0 {
			return 0
		}
		if s&lineTagMask == tag && t.lines[uint32(s)] == line {
			return rune(uint32(s))
		}
	}
}

// commonLinePrefix returns the length of the longest common prefix of a and b
// that ends at a line boundary.
func commonLinePrefix(a, b string) int {
	n, i := min(len(a), len(b)), 0
	for i+64 <= n && a[i:i+64] == b[i:i+64] {
		i += 64
	}
	for i < n && a[i] == b[i] {
		i++
	}
	return strings.LastIndexByte(a[:i], '\n') + 1
}

// commonLineSuffix returns the length of the longest common suffix of a and b
// that starts a line in both.
func commonLineSuffix(a, b string) int {
	n, i := min(len(a), len(b)), 0
	for i+64 <= n && a[len(a)-i-64:len(a)-i] == b[len(b)-i-64:len(b)-i] {
		i += 64
	}
	for i < n && a[len(a)-1-i] == b[len(b)-1-i] {
		i++
	}
	if (i == len(a) || a[len(a)-1-i] == '\n') && (i == len(b) || b[len(b)-1-i] == '\n') {
		return i
	}
	// Otherwise start after the first newline the suffix shares.
	if k := strings.IndexByte(a[len(a)-i:], '\n'); k >= 0 {
		return i - k - 1
	}
	return 0
}

// Line classes, as in Git's xdl_cleanup_records: a line absent from the other
// version, one that occurs there, and one that occurs there too often to be a
// meaningful match, such as a blank line or a closing brace.
const (
	lineAbsent = iota
	lineMatched
	lineCommon
)

// blankFlag marks whitespace-only lines for classifyLines. Most lines have a
// visible byte after their indentation; only non-ASCII input needs TrimSpace.
func blankFlag(line string) byte {
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case ' ', '\t', '\n', '\v', '\f', '\r':
			continue
		}
		if line[i] < utf8.RuneSelf {
			return 0
		}
		return blankFlagUnicode(line)
	}
	return 1
}

func blankFlagUnicode(line string) byte {
	if strings.TrimSpace(line) == "" {
		return 1
	}
	return 0
}

// classifyLines replaces each line's blankFlag with its class, from its count
// in the other version and Git's threshold of about the square root of the
// line count. Git counts whole files; only the changed middle is tokenized
// here, so lines that are common in any file, the blank ones, always count as
// common when the other version has them.
func classifyLines(classes []byte, lines []rune, other []int32) {
	limit := 1
	for n := len(lines); n > 0; n >>= 2 {
		limit <<= 1
	}
	limit = min(limit, 1024)
	for i, id := range lines {
		switch n := int(other[id]); {
		case n == 0:
			classes[i] = lineAbsent
		case n >= limit || classes[i] == 1:
			classes[i] = lineCommon
		default:
			classes[i] = lineMatched
		}
	}
}

// searchable reports whether line i takes part in the edit search. Like Git's
// xdl_clean_mmatch, a common line is left out when it sits among lines absent
// from the other version: matching it would cut a block of new lines, such as
// a private key with a blank line, into pieces that no longer match a rule.
func searchable(classes []byte, i int) bool {
	if classes[i] != lineCommon {
		return classes[i] == lineMatched
	}
	before, commonBefore := 0, 1
	for j := i - 1; j >= max(i-100, 0) && classes[j] != lineMatched; j-- {
		if classes[j] == lineAbsent {
			before++
		} else {
			commonBefore++
		}
	}
	if before == 0 {
		return true
	}
	after, commonAfter := 0, 1
	for j := i + 1; j <= min(i+100, len(classes)-1) && classes[j] != lineMatched; j++ {
		if classes[j] == lineAbsent {
			after++
		} else {
			commonAfter++
		}
	}
	if after == 0 {
		return true
	}
	common := commonBefore + commonAfter
	return common*4 >= common+before+after
}

func (w *worker) content(ctx context.Context, e gitobj.ChangeEntry) (string, bool, error) {
	if e.TreeEntry.Mode == filemode.Submodule {
		return "Subproject commit " + e.TreeEntry.Hash.String() + "\n", false, nil
	}
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	obj, err := w.store.read(e.TreeEntry.Hash)
	if err != nil {
		return "", false, err
	}
	if obj.kind != gitobj.BlobObject {
		return "", false, gitobj.ErrObjectNotFound
	}
	if obj.Size() > w.maxBlob {
		return "", false, limitf("blob %s size %d exceeds limit %d", e.TreeEntry.Hash, obj.Size(), w.maxBlob)
	}
	return obj.raw, strings.IndexByte(obj.raw[:min(len(obj.raw), binarySniffBytes)], 0) >= 0, nil
}

func (w *worker) archive(ctx context.Context, path, raw string, attrs map[string]string, yield sources.FragmentsFunc) error {
	if w.source.MaxArchiveDepth <= 0 {
		return nil
	}
	format, _, err := archives.Identify(ctx, path, nil)
	if errors.Is(err, archives.NoMatch) {
		return nil
	}
	if err != nil {
		return err
	}
	if format == nil {
		return nil
	}
	// Match filesystem scans: damaged archives warn without failing history traversal.
	source := filesystem.File{Logger: w.source.Logger, Content: contextReader{ctx, strings.NewReader(raw)}, Path: path, Attributes: attrs, Prefilter: w.source.Prefilter, MaxArchiveDepth: w.source.MaxArchiveDepth, StrictArchives: false, Symlink: "", DetectArchive: false}
	return source.Fragments(ctx, yield)
}
