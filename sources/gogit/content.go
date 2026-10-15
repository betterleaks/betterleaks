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
	ids            map[string]rune
	old, current   []rune
	positions      []int
	present, added []bool
}

func resize[T any](s []T, n int) []T {
	if cap(s) < n {
		return make([]T, n)
	}
	return s[:n]
}

// Lines absent from the other file cannot be matches. Remove them before the
// quadratic edit search, then map matching destination lines back to their
// original positions. This matters for generated files with tens of thousands
// of replaced lines; diffing those unmatched lines wastes almost all CPU time.
// As with Git's own preprocessing, ambiguous edit boundaries can differ from
// an unpruned diff. We preserve exact destination contents and line numbers.
func (d *lineDiffer) additions(ctx context.Context, src, dst string, emit func(string, int) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// These are the common-prefix cases the edit engine would remove anyway.
	// Require a line boundary: appending bytes to an unterminated final line
	// replaces that line instead of introducing a new one.
	if src == dst || (strings.HasPrefix(src, dst) && (dst == "" || dst[len(dst)-1] == '\n')) {
		return nil
	}
	if strings.HasPrefix(dst, src) && (src == "" || src[len(src)-1] == '\n') {
		return emit(strings.Clone(dst[len(src):]), strings.Count(src, "\n")+1)
	}
	// Tokens must fit the edit engine's Unicode alphabet. This also bounds the
	// bookkeeping allocated for a diff independently of its input byte limit.
	// Larger files are scanned whole, which can only add findings.
	if strings.Count(src, "\n")+strings.Count(dst, "\n")+2 > maxDiffLines {
		return emit(dst, 1)
	}
	// Only parent lines can be matches. Tokenize them once; destination-only
	// lines need neither IDs nor strings in the dictionary. Use valid Unicode
	// tokens because the edit engine serializes rune sequences as strings.
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
	d.old = resize(d.old, oldCount)
	a := d.old[:0]
	for offset := 0; offset < len(src); {
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
		a = append(a, id)
		offset = end
	}
	d.present = resize(d.present, len(ids)+1)
	present := d.present
	clear(present)
	d.current = resize(d.current, newCount)
	current := d.current[:0]
	d.positions = resize(d.positions, newCount)
	positions := d.positions[:0]
	for offset, pos := 0, 0; offset < len(dst); pos++ {
		end := strings.IndexByte(dst[offset:], '\n')
		if end < 0 {
			end = len(dst)
		} else {
			end += offset + 1
		}
		if id, ok := ids[dst[offset:end]]; ok {
			index := id
			if index >= 0xe000 {
				index -= 0x800
			}
			present[index] = true
			current = append(current, id)
			positions = append(positions, pos)
		}
		offset = end
	}
	old := a[:0]
	for _, id := range a {
		index := id
		if index >= 0xe000 {
			index -= 0x800
		}
		if present[index] {
			old = append(old, id)
		}
	}
	if len(current) == 0 {
		if dst == "" {
			return ctx.Err()
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return emit(dst, 1)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d.added = resize(d.added, newCount)
	added := d.added
	for i := range added {
		added[i] = true
	}
	// The edit engine has no context hook. Bound its synchronous search rather
	// than leaving a background goroutine running after cancellation. A search
	// that runs out of time returns an approximate edit script, so scan the
	// whole file instead: that can repeat findings but never drops any.
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
		return emit(dst, 1)
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
	// and the final unterminated line retains its original bytes. Clone emitted
	// slices so a small queued addition cannot keep an entire large blob alive.
	offset, begin, first := 0, -1, 0
	for i, yes := range added {
		if yes && begin < 0 {
			begin = offset
			first = i + 1
		}
		if !yes && begin >= 0 {
			if err := emit(strings.Clone(dst[begin:offset]), first); err != nil {
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
		if begin == 0 && offset == len(dst) {
			return emit(dst, first)
		}
		return emit(strings.Clone(dst[begin:offset]), first)
	}
	return ctx.Err()
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
