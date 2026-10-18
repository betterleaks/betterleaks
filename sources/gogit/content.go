package gogit

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/filemode"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/mholt/archives"
	"github.com/sergi/go-diff/diffmatchpatch"
)

func (w *worker) change(ctx context.Context, c *object.Change, attrs map[string]string, yield sources.FragmentsFunc) error {
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
		return w.archive(ctx, c.To, attrs, yield)
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
	ids          map[string]rune
	old, current []rune
	positions    []int
	inOld, inNew []int32
	classes      []byte
	added        []bool
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
	// Tokens must fit the edit engine's Unicode alphabet. This also bounds the
	// bookkeeping allocated for a diff independently of its input byte limit.
	// Larger changes are scanned whole, which can only add findings.
	if strings.Count(src, "\n")+strings.Count(dst, "\n")+2 > maxDiffLines {
		return add(dst, 1)
	}
	// Tokenize parent lines once; destination-only lines need neither IDs nor
	// strings in the dictionary. Use valid Unicode tokens because the edit
	// engine serializes rune sequences as strings.
	lineCount := func(text string) int {
		n := strings.Count(text, "\n")
		if len(text) > 0 && text[len(text)-1] != '\n' {
			n++
		}
		return n
	}
	oldCount, newCount := lineCount(src), lineCount(dst)
	if d.ids == nil {
		d.ids = make(map[string]rune, min(oldCount, 65536))
	}
	ids := d.ids
	defer func() {
		if len(ids) > 4096 {
			// Clearing a large map visits its whole capacity, even for the many
			// tiny files that follow it. Retain only the common small dictionaries.
			d.ids = nil
		} else {
			clear(ids)
		}
		if oldCount > 65536 || newCount > 65536 {
			*d = lineDiffer{}
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
		id, ok := ids[line]
		if !ok {
			id = rune(len(ids) + 1)
			if id >= 0xd800 {
				id += 0x800
			}
			ids[line] = id
		}
		oldClasses[len(a)] = blankFlag(line)
		a = append(a, id)
		offset = end
	}
	// Count every line in both versions. Destination-only lines get ID 0.
	d.inOld, d.inNew = resize(d.inOld, len(ids)+1), resize(d.inNew, len(ids)+1)
	inOld, inNew := d.inOld, d.inNew
	clear(inOld)
	clear(inNew)
	for _, id := range a {
		inOld[slot(id)]++
	}
	d.current = resize(d.current, newCount)
	b := d.current
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
		b[pos] = ids[dst[offset:end]]
		inNew[slot(b[pos])]++
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
	d.added = resize(d.added, newCount)
	added := d.added
	for i := range added {
		added[i] = true
	}
	// The edit engine has no context hook. Bound its synchronous search rather
	// than leaving a background goroutine running after cancellation. A search
	// that runs out of time returns an approximate edit script, so scan the
	// whole change instead: that can repeat findings but never drops any.
	dmp := diffmatchpatch.New()
	dmp.DiffTimeout = diffTimeout
	if deadline, ok := ctx.Deadline(); ok {
		dmp.DiffTimeout = min(dmp.DiffTimeout, max(time.Until(deadline), time.Nanosecond))
	}
	started := time.Now()
	chunks := dmp.DiffMainRunes(old, current, false)
	if err := ctx.Err(); err != nil {
		return err
	}
	if time.Since(started) >= dmp.DiffTimeout {
		return add(dst, 1)
	}
	at := 0
	for _, chunk := range chunks {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := utf8.RuneCountInString(chunk.Text)
		switch chunk.Type {
		case diffmatchpatch.DiffEqual:
			for _, pos := range positions[at : at+n] {
				added[pos] = false
			}
			at += n
		case diffmatchpatch.DiffInsert:
			at += n
		}
	}
	// Slice original bytes directly. No equal/deleted contents are reconstructed,
	// and the final unterminated line retains its original bytes.
	offset, begin, first := 0, -1, 0
	for i, yes := range added {
		if yes && begin < 0 {
			begin = offset
			first = i + 1
		}
		if !yes && begin >= 0 {
			if err := add(dst[begin:offset], first); err != nil {
				return err
			}
			begin = -1
		}
		end := strings.IndexByte(dst[offset:], '\n')
		if end < 0 {
			offset = len(dst)
		} else {
			offset += end + 1
		}
	}
	if begin >= 0 {
		return add(dst[begin:offset], first)
	}
	return ctx.Err()
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

// slot maps a line token to a dense index; tokens skip the surrogate range.
func slot(id rune) int {
	if id >= 0xe000 {
		return int(id - 0x800)
	}
	return int(id)
}

// Line classes, as in Git's xdl_cleanup_records: a line absent from the other
// version, one that occurs there, and one that occurs there too often to be a
// meaningful match, such as a blank line or a closing brace.
const (
	lineAbsent = iota
	lineMatched
	lineCommon
)

// blankFlag marks whitespace-only lines for classifyLines.
func blankFlag(line string) byte {
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
		switch n := int(other[slot(id)]); {
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

func (w *worker) content(ctx context.Context, e object.ChangeEntry) (string, bool, error) {
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
	if obj.kind != plumbing.BlobObject {
		return "", false, plumbing.ErrObjectNotFound
	}
	if obj.Size() > w.maxBlob {
		return "", false, limitf("blob %s size %d exceeds limit %d", e.TreeEntry.Hash, obj.Size(), w.maxBlob)
	}
	return obj.raw, strings.IndexByte(obj.raw[:min(len(obj.raw), binarySniffBytes)], 0) >= 0, nil
}

func (w *worker) archive(ctx context.Context, e object.ChangeEntry, attrs map[string]string, yield sources.FragmentsFunc) error {
	if w.source.MaxArchiveDepth <= 0 {
		return nil
	}
	format, _, err := archives.Identify(ctx, e.Name, nil)
	if errors.Is(err, archives.NoMatch) {
		return nil
	}
	if err != nil {
		return err
	}
	if format == nil {
		return nil
	}
	file, err := w.store.read(e.TreeEntry.Hash)
	if err != nil {
		return err
	}
	r, err := file.Reader()
	if err != nil {
		return err
	}
	defer r.Close()
	// Match filesystem scans: damaged archives warn without failing history traversal.
	source := sources.File{Logger: w.source.Logger, Content: contextReader{ctx, r}, Path: e.Name, Attributes: attrs, Prefilter: w.source.Prefilter, MaxArchiveDepth: w.source.MaxArchiveDepth, StrictArchives: false}
	return source.Fragments(ctx, yield)
}
