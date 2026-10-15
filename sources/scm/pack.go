//nolint:exhaustruct // Pack state is populated incrementally after input validation.
package scm

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/betterleaks/betterleaks/v2/internal/gitpack"
	"github.com/go-git/go-billy/v6/osfs"
	"github.com/go-git/go-git/v6/plumbing"
	format "github.com/go-git/go-git/v6/plumbing/format/config"
	githash "github.com/go-git/go-git/v6/plumbing/hash"
	"github.com/go-git/go-git/v6/storage/filesystem"
	"golang.org/x/sync/errgroup"
)

// Fetching must index every object, including ones the scan later skips, so no
// limit may reject a pack Git writes. Plain objects are streamed at any size.
// Delta bases and results are held in memory up to objectBytes each; cacheBytes
// is how much of the delta chains being resolved is kept before their oldest
// links are dropped and rebuilt on demand. Git never writes chains deeper than
// 4,095 links (pack.depth's maximum) and deltifies only objects under
// core.bigFileThreshold.
type packLimits struct {
	objectBytes, cacheBytes int64
	depth                   int
}

func fetchPackLimits() packLimits {
	return packLimits{objectBytes: 4 << 30, cacheBytes: 1 << 30, depth: 4096}
}

// packStorage overrides only fetch-time indexing. The stock writer retains all
// reconstructed objects until parsing ends. This writer spools the pack to disk
// and validates it as it arrives, like git index-pack --stdin, then resolves
// deltas in parallel with a bounded chain cache per worker. It is for fresh
// clones: thin packs with bases outside the received pack are rejected.
type packStorage struct {
	*filesystem.Storage
	ctx    context.Context
	dir    string
	limits packLimits
}

func (s *packStorage) PackfileWriter() (io.WriteCloser, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	cfg, err := s.Config()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(s.dir, "tmp_fetch_")
	if err != nil {
		return nil, err
	}
	f, err := os.Create(filepath.Join(dir, "pack"))
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	w := &packWriter{s: s, file: f, dir: dir, scanned: make(chan struct{})}
	w.cond = sync.NewCond(&w.mu)
	w.stopWake = context.AfterFunc(s.ctx, w.wake)
	go func() {
		defer close(w.scanned)
		w.table, w.scanErr = scanPack(s.ctx, &packTail{w: w}, cfg.Extensions.ObjectFormat, s.limits)
	}()
	return w, nil
}

// packWriter spools the pack to disk while the first pass reads it back, so
// validation and hashing overlap the download. Do not embed os.File: its
// ReadFrom would let io.Copy bypass Write's checks.
type packWriter struct {
	s        *packStorage
	file     *os.File
	dir      string
	err      error
	closed   bool
	stopWake func() bool

	mu      sync.Mutex
	cond    *sync.Cond
	written int64 // Guarded by mu.
	done    bool  // Guarded by mu: no more writes.

	scanned chan struct{} // Closed when the first pass returns.
	table   *packTable
	scanErr error
}

// wake lets a first pass waiting for data observe cancellation.
func (w *packWriter) wake() {
	w.mu.Lock()
	w.cond.Broadcast()
	w.mu.Unlock()
}

func (w *packWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, os.ErrClosed
	}
	if w.err != nil {
		return 0, w.err
	}
	if w.err = w.s.ctx.Err(); w.err != nil {
		return 0, w.err
	}
	select {
	case <-w.scanned:
		// The first pass waits for Close after the checksum, so ending
		// early means the pack is invalid: stop downloading it.
		if w.scanErr != nil {
			w.err = w.scanErr
			return 0, w.err
		}
	default:
	}
	n, err := w.file.Write(p)
	w.mu.Lock()
	w.written += int64(n)
	w.cond.Broadcast()
	w.mu.Unlock()
	w.err = err
	return n, err
}

// packTail reads the pack as it is written, waiting for more until Close.
type packTail struct {
	w   *packWriter
	off int64
}

func (t *packTail) Read(p []byte) (int, error) {
	w := t.w
	w.mu.Lock()
	for t.off == w.written && !w.done && w.s.ctx.Err() == nil {
		w.cond.Wait()
	}
	written := w.written
	w.mu.Unlock()
	if err := w.s.ctx.Err(); err != nil {
		return 0, err
	}
	if t.off == written {
		return 0, io.EOF
	}
	n, err := w.file.ReadAt(p[:min(int64(len(p)), written-t.off)], t.off)
	t.off += int64(n)
	return n, err
}

//nolint:nonamedreturns // Deferred rollback and idempotent Close need the final error.
func (w *packWriter) Close() (err error) {
	if w.closed {
		return w.err
	}
	w.closed = true
	w.mu.Lock()
	w.done = true
	w.cond.Broadcast()
	w.mu.Unlock()
	<-w.scanned
	w.stopWake()
	defer func() { w.err = err; w.file.Close(); os.RemoveAll(w.dir) }()
	if w.err != nil {
		return w.err
	}
	if err := w.s.ctx.Err(); err != nil {
		return err
	}
	if w.written == 0 {
		return nil
	}
	if w.scanErr != nil {
		return fmt.Errorf("index fetched pack: %w", w.scanErr)
	}
	if err := w.file.Close(); err != nil {
		return err
	}
	idxPath := filepath.Join(w.dir, "index")
	out, err := os.Create(idxPath)
	if err != nil {
		return err
	}
	revPath := filepath.Join(w.dir, "reverse-index")
	rev, err := os.Create(revPath)
	if err != nil {
		out.Close()
		return err
	}
	// Resolving reads delta records all over the pack. A read-only mapping
	// avoids a system call per record where the platform supports it.
	pack, err := osfs.New(w.dir, osfs.WithMmap()).Open("pack")
	if err == nil {
		err = indexTable(w.s.ctx, pack, w.table, w.s.limits, out, rev)
		err = errors.Join(err, pack.Close())
	}
	err = errors.Join(err, out.Close(), rev.Close())
	if err != nil {
		return fmt.Errorf("index fetched pack: %w", err)
	}
	if err := w.s.ctx.Err(); err != nil {
		return err
	}
	base := filepath.Join(w.s.dir, "pack-"+w.table.checksum.String())
	// Exclusive links publish complete files without replacing an existing pack.
	// Refs are updated by go-git only after Close succeeds. Roll back installed files
	// on publication/reindex failure; temporary files are always removed above.
	var installed []string
	defer func() {
		if err != nil {
			for _, path := range installed {
				os.Remove(path)
			}
		}
	}()
	for _, file := range []struct{ from, ext string }{{w.file.Name(), ".pack"}, {idxPath, ".idx"}, {revPath, ".rev"}} {
		if err := os.Link(file.from, base+file.ext); err != nil {
			return err
		}
		installed = append(installed, base+file.ext)
	}
	if err := w.s.ctx.Err(); err != nil {
		return err
	}
	if err := w.s.Reindex(); err != nil {
		return err
	}
	return w.s.ctx.Err()
}

// packRecord is kept for every object, so it is small: 32 bytes, with the ID
// stored in packTable.ids. Child/next are one-based indexes, with zero marking
// the end of a list. Keeping adjacency in the record table avoids a map and
// slice allocation per OFS delta.
type packRecord struct {
	offset, size int64
	crc          uint32
	child, next  uint32
	header       uint8               // Bytes from offset to the compressed content.
	kind, typ    plumbing.ObjectType // Original record kind, resolved type.
}

func (o *packRecord) content() int64 { return o.offset + int64(o.header) }

// packTable is the first pass's result: every record in pack order, with OFS
// deltas linked from their base and REF deltas listed by base ID.
type packTable struct {
	format      format.ObjectFormat
	objects     []packRecord
	ids         []byte // Each record's ID, idSize bytes apiece; zero until resolved.
	idSize      int
	refChildren map[[32]byte]uint32
	checksum    plumbing.Hash
	end         int64 // Where the trailing checksum starts.
}

func (t *packTable) id(i int) []byte { return t.ids[i*t.idSize : (i+1)*t.idSize] }

// idKey pads an ID to a fixed-size map key.
func idKey(id []byte) [32]byte {
	var key [32]byte
	copy(key[:], id)
	return key
}

// packInput hashes exactly the bytes consumed, including entry headers. Its
// ReadByte method prevents zlib from reading into the next record, so CRCs and
// content offsets remain correct despite bufio's read-ahead.
type packInput struct {
	ctx      context.Context
	r        *bufio.Reader
	offset   int64
	checksum hash.Hash
	crc      hash.Hash32
	pending  [4096]byte
	n        int
}

func (r *packInput) flush() {
	r.checksum.Write(r.pending[:r.n])
	r.crc.Write(r.pending[:r.n])
	r.n = 0
}

func (r *packInput) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	r.flush()
	n, err := r.r.Read(p)
	r.offset += int64(n)
	r.checksum.Write(p[:n])
	r.crc.Write(p[:n])
	return n, err
}

func (r *packInput) ReadByte() (byte, error) {
	if r.n == 0 {
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
	}
	b, err := r.r.ReadByte()
	if err != nil {
		return 0, err
	}
	r.offset++
	// Batch single-byte reads from flate. Hashing a freshly allocated one-byte
	// slice here would otherwise allocate almost once per compressed byte.
	r.pending[r.n] = b
	r.n++
	if r.n == len(r.pending) {
		r.flush()
	}
	return b, nil
}

type packContextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r packContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

type packContextWriter struct {
	ctx context.Context
	w   io.Writer
}

func (w packContextWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return w.w.Write(p)
}

// packInflater is reused across records, including on the resolving pass.
type packInflater struct {
	z   io.ReadCloser
	buf [32 << 10]byte
}

func (z *packInflater) copy(ctx context.Context, dst io.Writer, src io.Reader, size int64) error {
	var err error
	if z.z == nil {
		z.z, err = zlib.NewReader(src)
	} else {
		err = z.z.(zlib.Resetter).Reset(src, nil)
	}
	if err != nil {
		return err
	}
	n, err := io.CopyBuffer(dst, io.LimitReader(packContextReader{ctx, z.z}, size+1), z.buf[:])
	if closeErr := z.z.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if n != size {
		return errors.New("git packed object size mismatch")
	}
	return ctx.Err()
}

// indexPack indexes a complete pack: the fetch runs the same passes, the first
// one while the pack downloads.
func indexPack(ctx context.Context, f io.ReaderAt, size int64, objectFormat format.ObjectFormat, limits packLimits, out, reverse io.Writer) (plumbing.Hash, error) {
	t, err := scanPack(ctx, io.NewSectionReader(f, 0, size), objectFormat, limits)
	if err == nil {
		err = indexTable(ctx, f, t, limits, out, reverse)
	}
	if err != nil {
		return plumbing.Hash{}, err
	}
	return t.checksum, nil
}

// scanPack reads the pack once from start to end. It validates every record,
// hashes plain objects, links each delta to its base, and checks the trailing
// checksum, streaming every inflated record through a fixed buffer.
func scanPack(ctx context.Context, src io.Reader, objectFormat format.ObjectFormat, limits packLimits) (*packTable, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if objectFormat == format.UnsetObjectFormat {
		objectFormat = format.SHA1
	}
	h, err := githash.FromObjectFormat(objectFormat)
	if err != nil {
		return nil, err
	}
	r := &packInput{ctx: ctx, r: bufio.NewReaderSize(src, 64<<10), checksum: h, crc: crc32.NewIEEE()}
	var header [12]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	version, count := binary.BigEndian.Uint32(header[4:8]), binary.BigEndian.Uint32(header[8:12])
	if string(header[:4]) != "PACK" || (version != 2 && version != 3) {
		return nil, errors.New("invalid Git pack header")
	}
	// Do not allocate from an untrusted header's count.
	t := &packTable{format: objectFormat, idSize: h.Size(), refChildren: make(map[[32]byte]uint32)}
	var inflater packInflater
	for range count {
		r.crc.Reset()
		o := packRecord{offset: r.offset}
		// Plain objects are only streamed through the hasher here, so any size is
		// fine; sizes of content held in memory are checked where it is held.
		header, err := gitpack.ReadHeader(r, o.offset, h.Size(), math.MaxInt64)
		if err != nil {
			return nil, fmt.Errorf("pack offset %d: %w", o.offset, err)
		}
		o.header, o.size, o.kind, o.typ = uint8(r.offset-o.offset), header.Size, header.Type, header.Type
		if o.kind.IsDelta() && o.size > limits.objectBytes {
			return nil, fmt.Errorf("delta at offset %d exceeds %d instruction bytes", o.offset, limits.objectBytes)
		}
		dst := io.Discard
		var objectHash plumbing.Hasher
		if !o.kind.IsDelta() {
			objectHash = plumbing.NewHasher(objectFormat, o.kind, o.size)
			dst = &objectHash
		}
		if err := inflater.copy(ctx, dst, r, o.size); err != nil {
			return nil, fmt.Errorf("pack offset %d: %w", o.offset, err)
		}
		if o.kind.IsDelta() {
			t.ids = append(t.ids, make([]byte, t.idSize)...)
		} else {
			t.ids = append(t.ids, objectHash.Sum().Bytes()...)
		}
		r.flush()
		o.crc = r.crc.Sum32()
		link := uint32(len(t.objects) + 1)
		switch o.kind {
		case plumbing.OFSDeltaObject:
			parent := sort.Search(len(t.objects), func(i int) bool { return t.objects[i].offset >= header.BaseOffset })
			if parent == len(t.objects) || t.objects[parent].offset != header.BaseOffset {
				return nil, errors.New("OFS delta base is not a pack record")
			}
			o.next, t.objects[parent].child = t.objects[parent].child, link
		case plumbing.REFDeltaObject:
			key := idKey(header.BaseID.Bytes())
			o.next, t.refChildren[key] = t.refChildren[key], link
		}
		t.objects = append(t.objects, o)
	}
	// The trailer is read past packInput: it is not part of its own checksum.
	t.end = r.offset
	t.checksum.ResetBySize(h.Size())
	if _, err := t.checksum.ReadFrom(r.r); err != nil {
		return nil, err
	}
	if !bytes.Equal(h.Sum(nil), t.checksum.Bytes()) {
		return nil, errors.New("git pack checksum mismatch")
	}
	if _, err := r.r.ReadByte(); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("git pack has trailing data or an incorrect object count")
		}
		return nil, err
	}
	return t, nil
}

// indexTable resolves every delta and writes the index and reverse index.
func indexTable(ctx context.Context, f io.ReaderAt, t *packTable, limits packLimits, out, reverse io.Writer) error {
	if err := resolvePack(ctx, f, t, limits); err != nil {
		return err
	}
	return writeIndex(ctx, t, out, reverse)
}

// writeIndex writes a version 2 .idx and a .rev, as git index-pack does, from
// one permutation of the records sorted by ID.
func writeIndex(ctx context.Context, t *packTable, out, reverse io.Writer) error {
	n := len(t.objects)
	order := make([]uint32, n)
	for i := range order {
		order[i] = uint32(i)
	}
	slices.SortFunc(order, func(a, b uint32) int { return bytes.Compare(t.id(int(a)), t.id(int(b))) })
	for k := 1; k < n; k++ {
		if bytes.Equal(t.id(int(order[k-1])), t.id(int(order[k]))) {
			return errors.New("fetched pack contains duplicate object IDs")
		}
	}
	var fanout [256]uint32
	for i := range n {
		fanout[t.id(i)[0]]++
	}
	for b := 1; b < len(fanout); b++ {
		fanout[b] += fanout[b-1]
	}
	idx := newChecksumWriter(ctx, out, t.format)
	idx.write([]byte{255, 't', 'O', 'c'})
	idx.uint32(2)
	for _, c := range fanout {
		idx.uint32(c)
	}
	for _, i := range order {
		idx.write(t.id(int(i)))
	}
	for _, i := range order {
		idx.uint32(t.objects[i].crc)
	}
	var large []int64
	for _, i := range order {
		if offset := t.objects[i].offset; offset > math.MaxInt32 {
			idx.uint32(1<<31 | uint32(len(large)))
			large = append(large, offset)
		} else {
			idx.uint32(uint32(offset))
		}
	}
	for _, offset := range large {
		idx.uint64(uint64(offset))
	}
	idx.write(t.checksum.Bytes())
	if err := idx.finish(); err != nil {
		return err
	}
	if reverse == nil {
		return nil
	}
	// The local scanner uses the reverse index to follow OFS deltas without
	// building a second in-memory offset map. Records are in pack order, so
	// the reverse index is the inverse of the sorted order.
	position := make([]uint32, n)
	for k, i := range order {
		position[i] = uint32(k)
	}
	rev := newChecksumWriter(ctx, reverse, t.format)
	rev.write([]byte("RIDX"))
	rev.uint32(1)
	if t.idSize == format.SHA256Size {
		rev.uint32(2)
	} else {
		rev.uint32(1)
	}
	for _, k := range position {
		rev.uint32(k)
	}
	rev.write(t.checksum.Bytes())
	return rev.finish()
}

// checksumWriter buffers output, hashes it, and ends it with the hash, as Git's
// index files do. The first error is kept and returned by finish.
type checksumWriter struct {
	w       *bufio.Writer
	out     io.Writer
	h       hash.Hash
	err     error
	scratch [8]byte
}

func newChecksumWriter(ctx context.Context, out io.Writer, objectFormat format.ObjectFormat) *checksumWriter {
	h, err := githash.FromObjectFormat(objectFormat)
	c := &checksumWriter{out: packContextWriter{ctx, out}, h: h, err: err}
	if err == nil {
		c.w = bufio.NewWriterSize(io.MultiWriter(c.out, h), 64<<10)
	}
	return c
}

func (c *checksumWriter) write(p []byte) {
	if c.err == nil {
		_, c.err = c.w.Write(p)
	}
}

func (c *checksumWriter) uint32(v uint32) {
	c.write(binary.BigEndian.AppendUint32(c.scratch[:0], v))
}

func (c *checksumWriter) uint64(v uint64) {
	c.write(binary.BigEndian.AppendUint64(c.scratch[:0], v))
}

func (c *checksumWriter) finish() error {
	if c.err == nil {
		c.err = c.w.Flush()
	}
	if c.err == nil {
		_, c.err = c.out.Write(c.h.Sum(nil))
	}
	return c.err
}

// resolvePack gives every delta its type and ID. The deltas under different
// bases are independent, so workers each take whole trees, with an equal share
// of cacheBytes for their chain. A REF delta joins the tree of whichever
// worker first learns its base's ID.
func resolvePack(ctx context.Context, f io.ReaderAt, t *packTable, limits packLimits) error {
	workers := runtime.GOMAXPROCS(0)
	g, ctx := errgroup.WithContext(ctx)
	var next atomic.Int64
	var refs sync.Mutex
	hasRefs := len(t.refChildren) > 0 // Read before any worker deletes from it.
	for range workers {
		r := &resolver{ctx: ctx, f: f, t: t, limits: limits, cacheBytes: limits.cacheBytes / int64(workers),
			refs: &refs, hasRefs: hasRefs, input: bufio.NewReaderSize(nil, 8192)}
		g.Go(func() error {
			// Claim records in pack order, a batch at a time, for locality.
			const batch = 64
			for {
				start := int(next.Add(batch)) - batch
				if start >= len(t.objects) {
					return nil
				}
				for i := start; i < min(start+batch, len(t.objects)); i++ {
					if err := r.tree(i); err != nil {
						return err
					}
				}
			}
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}
	for _, o := range t.objects {
		if o.typ.IsDelta() {
			return fmt.Errorf("delta at offset %d has no base in the fetched pack", o.offset)
		}
	}
	return nil
}

// resolver is one worker's state. chain is the delta chain being resolved,
// from its base down. Each link's content is kept while the chain fits in
// cacheBytes. Beyond that the oldest links are dropped, since they are needed
// last, and rebuilt from the nearest kept link if a sibling needs them, like
// git index-pack's delta base cache.
type resolver struct {
	ctx        context.Context
	f          io.ReaderAt
	t          *packTable
	limits     packLimits
	cacheBytes int64
	refs       *sync.Mutex // Guards t.refChildren.
	hasRefs    bool
	input      *bufio.Reader
	inflater   packInflater
	chain      []chainLink
	kept       int64
}

type chainLink struct {
	i       int
	content string
	kept    bool
}

func (r *resolver) inflate(i int) (string, error) {
	o := &r.t.objects[i]
	if o.size > r.limits.objectBytes {
		return "", fmt.Errorf("object at offset %d exceeds %d bytes", o.offset, r.limits.objectBytes)
	}
	// Read only this record's bytes: most are far smaller than the buffer, and
	// reading ahead would copy (or fault in) pages no other record here needs.
	end := r.t.end
	if i+1 < len(r.t.objects) {
		end = r.t.objects[i+1].offset
	}
	r.input.Reset(io.NewSectionReader(r.f, o.content(), end-o.content()))
	var b strings.Builder
	b.Grow(int(o.size))
	err := r.inflater.copy(r.ctx, &b, r.input, o.size)
	return b.String(), err
}

func (r *resolver) apply(base string, child int) (string, error) {
	delta, err := r.inflate(child)
	if err != nil {
		return "", err
	}
	target, err := gitpack.ApplyDelta(r.ctx, base, delta, r.limits.objectBytes)
	if err != nil {
		return "", fmt.Errorf("delta at offset %d: %w", r.t.objects[child].offset, err)
	}
	return target, nil
}

// takeRefs moves the REF deltas naming object i's ID onto its child list. A REF
// base's ID may only become known after resolving an OFS delta, so the list is
// taken once, by whichever worker learns that ID first; a duplicate object
// cannot claim it again.
func (r *resolver) takeRefs(i int) {
	if !r.hasRefs {
		return
	}
	objects := r.t.objects
	key := idKey(r.t.id(i))
	r.refs.Lock()
	pending := r.t.refChildren[key]
	delete(r.t.refChildren, key)
	r.refs.Unlock()
	for pending != 0 {
		child := int(pending - 1)
		next := objects[child].next
		objects[child].next, objects[i].child = objects[i].child, pending
		pending = next
	}
}

func (r *resolver) trim() {
	for k := 0; r.kept > r.cacheBytes && k < len(r.chain)-1; k++ {
		if r.chain[k].kept {
			r.kept -= int64(len(r.chain[k].content))
			r.chain[k] = chainLink{i: r.chain[k].i}
		}
	}
}

func (r *resolver) contentAt(level int) (string, error) {
	if r.chain[level].kept {
		return r.chain[level].content, nil
	}
	k := level
	for k > 0 && !r.chain[k].kept {
		k--
	}
	content := r.chain[k].content
	var err error
	if !r.chain[k].kept { // k is 0: the base was dropped too.
		content, err = r.inflate(r.chain[k].i)
	}
	for k++; err == nil && k <= level; k++ {
		content, err = r.apply(content, r.chain[k].i)
	}
	if err != nil {
		return "", err
	}
	r.chain[level] = chainLink{r.chain[level].i, content, true}
	r.kept += int64(len(content))
	r.trim()
	return content, nil
}

// tree resolves every delta under object i if i is a plain object.
func (r *resolver) tree(i int) error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	o := &r.t.objects[i]
	if o.kind.IsDelta() {
		return nil
	}
	r.takeRefs(i)
	if o.child == 0 {
		return nil
	}
	content, err := r.inflate(i)
	if err != nil {
		return err
	}
	r.chain, r.kept = append(r.chain[:0], chainLink{i, content, true}), int64(len(content))
	err = r.visit(0)
	// Clear the slots, not just the length: the backing array would otherwise
	// keep the contents alive outside the cache budget.
	clear(r.chain)
	r.chain, r.kept = r.chain[:0], 0
	return err
}

func (r *resolver) visit(level int) error {
	objects := r.t.objects
	i := r.chain[level].i
	for c := objects[i].child; c != 0; c = objects[c-1].next {
		child := int(c - 1)
		if err := r.ctx.Err(); err != nil {
			return err
		}
		if level >= r.limits.depth {
			return fmt.Errorf("fetch delta chain exceeds %d links", r.limits.depth)
		}
		base, err := r.contentAt(level)
		if err != nil {
			return err
		}
		target, err := r.apply(base, child)
		if err != nil {
			return err
		}
		objects[child].typ = objects[i].typ
		h := plumbing.NewHasher(r.t.format, objects[child].typ, int64(len(target)))
		if _, err := io.CopyBuffer(&h, packContextReader{r.ctx, strings.NewReader(target)}, r.inflater.buf[:]); err != nil {
			return err
		}
		copy(r.t.id(child), h.Sum().Bytes())
		r.takeRefs(child)
		r.chain = append(r.chain, chainLink{child, target, true})
		r.kept += int64(len(target))
		r.trim()
		err = r.visit(level + 1)
		if r.chain[level+1].kept {
			r.kept -= int64(len(r.chain[level+1].content))
		}
		r.chain[level+1] = chainLink{}
		r.chain = r.chain[:level+1]
		if err != nil {
			return err
		}
	}
	return nil
}
