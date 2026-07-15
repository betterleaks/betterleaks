// Package gitobject reads reachable blobs directly from Git packfiles.
package gitobject

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zlib"
	"golang.org/x/exp/mmap"
)

const (
	cacheLimit        = 64 << 20
	maxStreamBlobSize = 256 << 20
	cacheShards       = 16
)

type hash [20]byte

func (h hash) String() string { return hex.EncodeToString(h[:]) }

func parseHash(s string) (hash, error) {
	var h hash
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(h) {
		return h, fmt.Errorf("invalid object id %q", s)
	}
	copy(h[:], b)
	return h, nil
}

// Appearance identifies one reachable path for a blob.
type Appearance struct {
	Path        string
	Commit      string
	Message     string
	AuthorName  string
	AuthorEmail string
	AuthorTime  time.Time
}

// Blob is a decoded Git blob. Content is valid only during the callback.
type Blob struct {
	Hash       string
	Size       int64
	Content    io.Reader
	StartLine  int
	Binary     bool
	Appearance Appearance
}

type location struct {
	pack   *pack
	offset int64
}

type entry struct {
	hash   hash
	offset int64
}

type pack struct {
	order     int
	file      *mmap.ReaderAt
	index     []byte
	count     int
	hashesAt  int
	offsetsAt int
	largeAt   int
	offsets   []int64
	meta      []packMeta
}

type packMeta struct {
	typ        byte
	size       int64
	dataPos    int64
	baseOffset int64
	baseHash   hash
}

type object struct {
	typ  byte
	data []byte
}

type store struct {
	gitDir   string
	headDir  string
	packs    []*pack
	zlibPool sync.Pool
	cache    [cacheShards]cacheShard
}

type cacheShard struct {
	mu    sync.RWMutex
	cache map[cacheKey]object
	order []cacheKey
	head  int
	bytes int
}

type cacheKey struct {
	pack   *pack
	offset int64
	loose  hash
}

// Walk visits every blob reachable from a reference once. Packed blobs are
// visited by ascending pack offset for sequential I/O and delta locality.
func Walk(ctx context.Context, repoPath string, yield func(Blob) error) error {
	s, err := openStore(repoPath)
	if err != nil {
		return err
	}
	defer s.close()

	var appearances map[hash]Appearance
	if s.objectCount() > 100_000 {
		appearances, err = s.reachableBlobsConcurrent(ctx)
	} else {
		appearances, err = s.reachableBlobs(ctx)
	}
	if err != nil {
		return err
	}
	packed := make(map[*pack][]entry, len(s.packs))
	for h := range appearances {
		if loc, ok := s.find(h); ok {
			packed[loc.pack] = append(packed[loc.pack], entry{hash: h, offset: loc.offset})
		}
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan hash, 256)
	var workers sync.WaitGroup
	var firstErr error
	var errOnce sync.Once
	fail := func(err error) {
		errOnce.Do(func() {
			firstErr = err
			cancel()
		})
	}
	for range min(runtime.GOMAXPROCS(0), 8) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for h := range jobs {
				obj, err := s.load(h)
				if err != nil {
					fail(fmt.Errorf("read blob %s: %w", h, err))
					return
				}
				if obj.typ != 3 {
					fail(fmt.Errorf("object %s is not a blob", h))
					return
				}
				if err := yield(Blob{
					Hash:       h.String(),
					Size:       int64(len(obj.data)),
					Content:    bytes.NewReader(obj.data),
					Appearance: appearances[h],
				}); err != nil {
					fail(err)
					return
				}
			}
		}()
	}
	send := func(h hash) bool {
		select {
		case jobs <- h:
			return true
		case <-runCtx.Done():
			return false
		}
	}

	stopped := false
	for _, p := range s.packs {
		entries := packed[p]
		sort.Slice(entries, func(i, j int) bool { return entries[i].offset < entries[j].offset })
		for _, e := range entries {
			if !send(e.hash) {
				stopped = true
				break
			}
		}
		if stopped {
			break
		}
	}
	if !stopped {
		for h := range appearances {
			if _, ok := s.find(h); !ok && !send(h) {
				break
			}
		}
	}
	close(jobs)
	workers.Wait()
	if firstErr != nil {
		return firstErr
	}
	return runCtx.Err()
}

func (s *store) objectCount() int {
	var count int
	for _, p := range s.packs {
		count += p.count
	}
	return count
}

func (s *store) walkAllBlobs(ctx context.Context, yield func(Blob) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type job struct {
		pack   *pack
		offset int64
	}
	jobs := make(chan job, 256)
	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once
	fail := func(err error) {
		errOnce.Do(func() {
			firstErr = err
			cancel()
		})
	}
	for range min(runtime.GOMAXPROCS(0), 8) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				typ, size, err := s.objectInfo(job.pack, job.offset, 0)
				if err != nil {
					fail(err)
					return
				}
				if typ != 3 || size > maxStreamBlobSize {
					continue
				}
				obj, err := s.loadPack(job.pack, job.offset, 0)
				if err != nil {
					fail(err)
					return
				}
				if obj.typ == 3 {
					if err := yield(Blob{Size: int64(len(obj.data)), Content: bytes.NewReader(obj.data)}); err != nil {
						fail(err)
						return
					}
				}
			}
		}()
	}

send:
	for _, p := range s.packs {
		offsets := make([]int64, p.count)
		for i := range offsets {
			var ok bool
			offsets[i], ok = p.offsetAt(i)
			if !ok {
				return errors.New("invalid pack offset")
			}
		}
		sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
		for _, offset := range offsets {
			select {
			case jobs <- job{pack: p, offset: offset}:
			case <-ctx.Done():
				break send
			}
		}
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	return ctx.Err()
}

func (s *store) objectInfo(p *pack, offset int64, depth int) (byte, int64, error) {
	if depth > 128 {
		return 0, 0, errors.New("delta chain too deep")
	}
	r := bufio.NewReader(io.NewSectionReader(p.file, offset, 1<<63-1-offset))
	c, err := r.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	typ := (c >> 4) & 7
	size := int64(c & 15)
	for shift := uint(4); c&0x80 != 0; shift += 7 {
		if shift > 63 {
			return 0, 0, errors.New("invalid pack object size")
		}
		c, err = r.ReadByte()
		if err != nil {
			return 0, 0, err
		}
		size |= int64(c&0x7f) << shift
	}
	if typ >= 1 && typ <= 4 {
		return typ, size, nil
	}

	var basePack, baseOffset = p, int64(0)
	switch typ {
	case 6:
		c, err = r.ReadByte()
		if err != nil {
			return 0, 0, err
		}
		distance := int64(c & 0x7f)
		for c&0x80 != 0 {
			c, err = r.ReadByte()
			if err != nil {
				return 0, 0, err
			}
			distance = ((distance + 1) << 7) | int64(c&0x7f)
		}
		baseOffset = offset - distance
	case 7:
		var baseHash hash
		if _, err := io.ReadFull(r, baseHash[:]); err != nil {
			return 0, 0, err
		}
		loc, ok := s.find(baseHash)
		if !ok {
			obj, err := s.loadLoose(baseHash)
			if err != nil {
				return 0, 0, err
			}
			return obj.typ, int64(len(obj.data)), nil
		}
		basePack, baseOffset = loc.pack, loc.offset
	default:
		return 0, 0, errors.New("invalid pack object type")
	}

	zr, err := zlib.NewReader(r)
	if err != nil {
		return 0, 0, err
	}
	br := bufio.NewReader(zr)
	if _, err := binary.ReadUvarint(br); err != nil {
		_ = zr.Close()
		return 0, 0, err
	}
	resultSize, err := binary.ReadUvarint(br)
	_ = zr.Close()
	if err != nil || resultSize > uint64(^uint(0)>>1) {
		return 0, 0, errors.New("invalid delta result size")
	}
	baseType, _, err := s.objectInfo(basePack, baseOffset, depth+1)
	return baseType, int64(resultSize), err
}

func openStore(repoPath string) (*store, error) {
	gitDir, err := findGitDir(repoPath)
	if err != nil {
		return nil, fmt.Errorf("open repository: %w", err)
	}
	headDir := gitDir
	if data, err := os.ReadFile(filepath.Join(gitDir, "commondir")); err == nil {
		common := strings.TrimSpace(string(data))
		if !filepath.IsAbs(common) {
			common = filepath.Join(gitDir, common)
		}
		gitDir = filepath.Clean(common)
	}
	s := &store{gitDir: gitDir, headDir: headDir}
	idxFiles, err := filepath.Glob(filepath.Join(gitDir, "objects", "pack", "*.idx"))
	if err != nil {
		return nil, err
	}
	for _, idxPath := range idxFiles {
		p, err := readIndex(idxPath)
		if err != nil {
			s.close()
			return nil, fmt.Errorf("read %s: %w", idxPath, err)
		}
		p.file, err = mmap.Open(strings.TrimSuffix(idxPath, ".idx") + ".pack")
		if err != nil {
			s.close()
			return nil, err
		}
		if err := preparePack(p); err != nil {
			s.close()
			return nil, fmt.Errorf("index %s: %w", idxPath, err)
		}
		p.order = len(s.packs)
		s.packs = append(s.packs, p)
	}
	return s, nil
}

func preparePack(p *pack) error {
	headers := make([]struct {
		offset int64
		meta   packMeta
	}, p.count)
	for i := 0; i < p.count; i++ {
		offset, ok := p.offsetAt(i)
		if !ok {
			return errors.New("invalid pack offset")
		}
		var header [64]byte
		n, err := p.file.ReadAt(header[:], offset)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		pos := 0
		next := func() byte { b := header[pos]; pos++; return b }
		c := next()
		typ := (c >> 4) & 7
		size := int64(c & 15)
		for shift := uint(4); c&0x80 != 0; shift += 7 {
			if shift > 63 || pos >= n {
				return errors.New("invalid pack header")
			}
			c = next()
			size |= int64(c&0x7f) << shift
		}
		m := packMeta{typ: typ, size: size, dataPos: offset + int64(pos)}
		if typ == 6 {
			if pos >= n {
				return io.ErrUnexpectedEOF
			}
			c = next()
			distance := int64(c & 0x7f)
			for c&0x80 != 0 {
				if pos >= n {
					return io.ErrUnexpectedEOF
				}
				c = next()
				distance = ((distance + 1) << 7) | int64(c&0x7f)
			}
			m.baseOffset = offset - distance
		} else if typ == 7 {
			if pos+20 > n {
				return io.ErrUnexpectedEOF
			}
			copy(m.baseHash[:], header[pos:pos+20])
			pos += 20
		}
		m.dataPos = offset + int64(pos)
		headers[i] = struct {
			offset int64
			meta   packMeta
		}{offset, m}
	}
	sort.Slice(headers, func(i, j int) bool { return headers[i].offset < headers[j].offset })
	p.offsets = make([]int64, p.count)
	p.meta = make([]packMeta, p.count)
	for i, h := range headers {
		p.offsets[i], p.meta[i] = h.offset, h.meta
	}
	return nil
}

func (p *pack) metaAt(offset int64) (packMeta, bool) {
	i := sort.Search(len(p.offsets), func(i int) bool { return p.offsets[i] >= offset })
	if i == len(p.offsets) || p.offsets[i] != offset {
		return packMeta{}, false
	}
	return p.meta[i], true
}

func readIndex(path string) (*pack, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < 8+256*4 || string(b[:4]) != "\xfftOc" || binary.BigEndian.Uint32(b[4:8]) != 2 {
		return nil, errors.New("unsupported pack index (want v2)")
	}
	n := int(binary.BigEndian.Uint32(b[8+255*4 : 8+256*4]))
	hashesAt := 8 + 256*4
	offsetsAt := hashesAt + n*20 + n*4
	largeAt := offsetsAt + n*4
	if n < 0 || offsetsAt < hashesAt || largeAt < offsetsAt || largeAt > len(b)-40 {
		return nil, errors.New("truncated pack index")
	}
	return &pack{index: b, count: n, hashesAt: hashesAt, offsetsAt: offsetsAt, largeAt: largeAt}, nil
}

func (p *pack) find(h hash) (int64, bool) {
	i := sort.Search(p.count, func(i int) bool {
		return bytes.Compare(p.index[p.hashesAt+i*20:p.hashesAt+(i+1)*20], h[:]) >= 0
	})
	if i == p.count || !bytes.Equal(p.index[p.hashesAt+i*20:p.hashesAt+(i+1)*20], h[:]) {
		return 0, false
	}
	return p.offsetAt(i)
}

func (p *pack) offsetAt(i int) (int64, bool) {
	if i < 0 || i >= p.count {
		return 0, false
	}
	off := binary.BigEndian.Uint32(p.index[p.offsetsAt+i*4 : p.offsetsAt+(i+1)*4])
	if off&(1<<31) == 0 {
		return int64(off), true
	}
	pos := p.largeAt + int(off&^(1<<31))*8
	if pos < p.largeAt || pos+8 > len(p.index)-40 {
		return 0, false
	}
	return int64(binary.BigEndian.Uint64(p.index[pos : pos+8])), true
}

func (s *store) find(h hash) (location, bool) {
	for _, p := range s.packs {
		if offset, ok := p.find(h); ok {
			return location{pack: p, offset: offset}, true
		}
	}
	return location{}, false
}

func (s *store) close() {
	for _, p := range s.packs {
		if p.file != nil {
			_ = p.file.Close()
		}
	}
}

func (s *store) load(h hash) (object, error) {
	var obj object
	var err error
	var key cacheKey
	if loc, ok := s.find(h); ok {
		key = cacheKey{pack: loc.pack, offset: loc.offset}
		if obj, ok := s.getCache(key); ok {
			return obj, nil
		}
		return s.loadPack(loc.pack, loc.offset, 0)
	} else {
		key = cacheKey{loose: h}
		if obj, ok := s.getCache(key); ok {
			return obj, nil
		}
		obj, err = s.loadLoose(h)
	}
	if err == nil {
		s.putCache(key, obj)
	}
	return obj, err
}

func (s *store) loadPack(p *pack, offset int64, depth int) (object, error) {
	if depth > 128 {
		return object{}, errors.New("delta chain too deep")
	}
	key := cacheKey{pack: p, offset: offset}
	if obj, ok := s.getCache(key); ok {
		return obj, nil
	}
	meta, ok := p.metaAt(offset)
	if !ok {
		return object{}, errors.New("pack object offset not indexed")
	}
	typ, size := meta.typ, meta.size
	var err error

	var base object
	switch typ {
	case 6:
		base, err = s.loadPack(p, meta.baseOffset, depth+1)
	case 7:
		base, err = s.load(meta.baseHash)
	}
	if err != nil {
		return object{}, err
	}

	if size < 0 || uint64(size) > uint64(^uint(0)>>1) {
		return object{}, errors.New("pack object too large")
	}
	r := io.NewSectionReader(p.file, meta.dataPos, 1<<63-1-meta.dataPos)
	data, err := s.inflate(r, int(size))
	if err != nil {
		return object{}, err
	}
	if typ == 6 || typ == 7 {
		data, err = applyDelta(base.data, data)
		if err != nil {
			return object{}, err
		}
		typ = base.typ
	} else if int64(len(data)) != size {
		return object{}, errors.New("pack object size mismatch")
	}
	obj := object{typ: typ, data: data}
	s.putCache(key, obj)
	return obj, nil
}

func applyDelta(base, delta []byte) ([]byte, error) {
	baseSize, delta, ok := deltaSize(delta)
	if !ok || baseSize != uint64(len(base)) {
		return nil, errors.New("invalid delta base size")
	}
	resultSize, delta, ok := deltaSize(delta)
	if !ok || resultSize > uint64(^uint(0)>>1) {
		return nil, errors.New("invalid delta result size")
	}
	out := make([]byte, 0, int(resultSize))
	for len(delta) > 0 {
		cmd := delta[0]
		delta = delta[1:]
		if cmd&0x80 == 0 {
			if cmd == 0 || int(cmd) > len(delta) {
				return nil, errors.New("invalid delta insert")
			}
			out = append(out, delta[:cmd]...)
			delta = delta[cmd:]
			continue
		}
		var off, size uint32
		for i, shift := 0, uint(0); i < 4; i, shift = i+1, shift+8 {
			if cmd&(1<<i) != 0 {
				if len(delta) == 0 {
					return nil, errors.New("truncated delta copy offset")
				}
				off |= uint32(delta[0]) << shift
				delta = delta[1:]
			}
		}
		for i, shift := 0, uint(0); i < 3; i, shift = i+1, shift+8 {
			if cmd&(1<<(4+i)) != 0 {
				if len(delta) == 0 {
					return nil, errors.New("truncated delta copy size")
				}
				size |= uint32(delta[0]) << shift
				delta = delta[1:]
			}
		}
		if size == 0 {
			size = 0x10000
		}
		end := uint64(off) + uint64(size)
		if end > uint64(len(base)) {
			return nil, errors.New("delta copy outside base")
		}
		out = append(out, base[off:uint32(end)]...)
	}
	if uint64(len(out)) != resultSize {
		return nil, errors.New("delta result size mismatch")
	}
	return out, nil
}

func deltaSize(b []byte) (uint64, []byte, bool) {
	var n uint64
	for shift := uint(0); shift < 64 && len(b) > 0; shift += 7 {
		c := b[0]
		b = b[1:]
		n |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return n, b, true
		}
	}
	return 0, b, false
}

func (s *store) loadLoose(h hash) (object, error) {
	path := filepath.Join(s.gitDir, "objects", hex.EncodeToString(h[:1]), hex.EncodeToString(h[1:]))
	f, err := os.Open(path)
	if err != nil {
		return object{}, err
	}
	defer f.Close()
	b, err := s.inflate(f, -1)
	if err != nil {
		return object{}, err
	}
	nul := bytes.IndexByte(b, 0)
	if nul < 0 {
		return object{}, errors.New("invalid loose object header")
	}
	parts := strings.SplitN(string(b[:nul]), " ", 2)
	if len(parts) != 2 {
		return object{}, errors.New("invalid loose object header")
	}
	typ := map[string]byte{"commit": 1, "tree": 2, "blob": 3, "tag": 4}[parts[0]]
	size, err := strconv.Atoi(parts[1])
	if typ == 0 || err != nil || size != len(b)-nul-1 {
		return object{}, errors.New("invalid loose object")
	}
	return object{typ: typ, data: b[nul+1:]}, nil
}

func (s *store) inflate(r io.Reader, size int) ([]byte, error) {
	var zr io.ReadCloser
	if pooled := s.zlibPool.Get(); pooled != nil {
		zr = pooled.(io.ReadCloser)
		if err := zr.(zlib.Resetter).Reset(r, nil); err != nil {
			return nil, err
		}
	} else {
		var err error
		zr, err = zlib.NewReader(r)
		if err != nil {
			return nil, err
		}
	}
	var (
		data []byte
		err  error
	)
	if size >= 0 {
		data = make([]byte, size)
		_, err = io.ReadFull(zr, data)
	} else {
		data, err = io.ReadAll(zr)
	}
	closeErr := zr.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	s.zlibPool.Put(zr)
	return data, nil
}

func (s *store) putCache(key cacheKey, obj object) {
	sh := &s.cache[cacheShardIndex(key)]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.cache == nil {
		sh.cache = make(map[cacheKey]object)
	}
	if _, ok := sh.cache[key]; ok || len(obj.data) > cacheLimit/cacheShards {
		return
	}
	sh.cache[key] = obj
	sh.order = append(sh.order, key)
	sh.bytes += len(obj.data)
	for sh.bytes > cacheLimit/cacheShards {
		old := sh.order[sh.head]
		sh.head++
		sh.bytes -= len(sh.cache[old].data)
		delete(sh.cache, old)
	}
	if sh.head > 4096 && sh.head*2 > len(sh.order) {
		sh.order = append(sh.order[:0], sh.order[sh.head:]...)
		sh.head = 0
	}
}

func (s *store) getCache(key cacheKey) (object, bool) {
	sh := &s.cache[cacheShardIndex(key)]
	sh.mu.RLock()
	defer sh.mu.RUnlock()
	obj, ok := sh.cache[key]
	return obj, ok
}

func cacheShardIndex(key cacheKey) int {
	if key.pack != nil {
		return int(uint64(key.offset)>>4) & (cacheShards - 1)
	}
	return int(key.loose[0]) & (cacheShards - 1)
}

func (s *store) reachableBlobs(ctx context.Context) (map[hash]Appearance, error) {
	tips, err := s.references()
	if err != nil {
		return nil, err
	}
	blobs := make(map[hash]Appearance)
	seenCommits := make(map[hash]bool)
	seenTrees := make(map[hash]bool)
	var visitCommit func(hash) error
	visitCommit = func(id hash) error {
		if seenCommits[id] {
			return nil
		}
		seenCommits[id] = true
		if err := ctx.Err(); err != nil {
			return err
		}
		obj, err := s.load(id)
		if err != nil {
			return err
		}
		for obj.typ == 4 {
			id, err = tagTarget(obj.data)
			if err != nil {
				return err
			}
			obj, err = s.load(id)
			if err != nil {
				return err
			}
		}
		if obj.typ != 1 {
			return nil
		}
		commit, err := parseCommit(id, obj.data)
		if err != nil {
			return err
		}
		if err := s.visitTree(ctx, commit.tree, "", commit.appearance, seenTrees, blobs); err != nil {
			return err
		}
		for _, parent := range commit.parents {
			if err := visitCommit(parent); err != nil {
				return err
			}
		}
		return nil
	}
	for _, tip := range tips {
		if err := visitCommit(tip); err != nil {
			return nil, fmt.Errorf("walk commits: %w", err)
		}
	}
	return blobs, nil
}

type graphWalk struct {
	mu          sync.Mutex
	cond        *sync.Cond
	queue       []hash
	pending     int
	err         error
	seenCommits map[hash]bool
	seenTrees   map[hash]bool
	blobs       map[hash]Appearance
}

func (s *store) reachableBlobsConcurrent(ctx context.Context) (map[hash]Appearance, error) {
	tips, err := s.references()
	if err != nil {
		return nil, err
	}
	state := &graphWalk{
		seenCommits: make(map[hash]bool),
		seenTrees:   make(map[hash]bool),
		blobs:       make(map[hash]Appearance),
	}
	state.cond = sync.NewCond(&state.mu)
	for _, tip := range tips {
		state.enqueue(tip)
	}

	var workers sync.WaitGroup
	for range min(runtime.GOMAXPROCS(0), 8) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				id, ok := state.next()
				if !ok {
					return
				}
				parents, err := s.visitCommitConcurrent(ctx, id, state)
				state.done(parents, err)
			}
		}()
	}
	workers.Wait()
	if state.err != nil {
		return nil, fmt.Errorf("walk commits: %w", state.err)
	}
	return state.blobs, nil
}

func (w *graphWalk) enqueue(id hash) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.enqueueLocked(id)
}

func (w *graphWalk) enqueueLocked(id hash) {
	if !w.seenCommits[id] {
		w.seenCommits[id] = true
		w.queue = append(w.queue, id)
		w.pending++
		w.cond.Signal()
	}
}

func (w *graphWalk) next() (hash, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for len(w.queue) == 0 && w.pending > 0 && w.err == nil {
		w.cond.Wait()
	}
	if w.err != nil || w.pending == 0 {
		return hash{}, false
	}
	id := w.queue[len(w.queue)-1]
	w.queue = w.queue[:len(w.queue)-1]
	return id, true
}

func (w *graphWalk) done(parents []hash, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err != nil && w.err == nil {
		w.err = err
	}
	if w.err == nil {
		for _, parent := range parents {
			w.enqueueLocked(parent)
		}
	}
	w.pending--
	w.cond.Broadcast()
}

func (s *store) visitCommitConcurrent(ctx context.Context, id hash, state *graphWalk) ([]hash, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	obj, err := s.load(id)
	if err != nil {
		return nil, err
	}
	for obj.typ == 4 {
		id, err = tagTarget(obj.data)
		if err != nil {
			return nil, err
		}
		obj, err = s.load(id)
		if err != nil {
			return nil, err
		}
	}
	if obj.typ != 1 {
		return nil, nil
	}
	commit, err := parseCommit(id, obj.data)
	if err != nil {
		return nil, err
	}
	if err := s.visitTreeConcurrent(ctx, commit.tree, "", commit.appearance, state); err != nil {
		return nil, err
	}
	return commit.parents, nil
}

func (s *store) visitTreeConcurrent(ctx context.Context, id hash, prefix string, appearance Appearance, state *graphWalk) error {
	state.mu.Lock()
	if state.seenTrees[id] {
		state.mu.Unlock()
		return nil
	}
	state.seenTrees[id] = true
	state.mu.Unlock()

	obj, err := s.load(id)
	if err != nil {
		return err
	}
	if obj.typ != 2 {
		return errors.New("tree id is not a tree")
	}
	for data := obj.data; len(data) > 0; {
		space, nul := bytes.IndexByte(data, ' '), bytes.IndexByte(data, 0)
		if space < 1 || nul < space || nul+21 > len(data) {
			return errors.New("invalid tree object")
		}
		mode, name := string(data[:space]), string(data[space+1:nul])
		var child hash
		copy(child[:], data[nul+1:nul+21])
		data = data[nul+21:]
		path := name
		if prefix != "" {
			path = prefix + "/" + name
		}
		if mode == "40000" || mode == "040000" {
			if err := s.visitTreeConcurrent(ctx, child, path, appearance, state); err != nil {
				return err
			}
		} else if mode == "100644" || mode == "100755" {
			state.mu.Lock()
			if _, ok := state.blobs[child]; !ok {
				a := appearance
				a.Path = path
				state.blobs[child] = a
			}
			state.mu.Unlock()
		}
	}
	return ctx.Err()
}

type commitData struct {
	tree       hash
	parents    []hash
	appearance Appearance
}

func parseCommit(id hash, data []byte) (commitData, error) {
	var c commitData
	c.appearance.Commit = id.String()
	header, message, _ := bytes.Cut(data, []byte("\n\n"))
	c.appearance.Message = string(message)
	for _, line := range bytes.Split(header, []byte{'\n'}) {
		key, value, ok := bytes.Cut(line, []byte{' '})
		if !ok {
			continue
		}
		switch string(key) {
		case "tree":
			var err error
			c.tree, err = parseHash(string(value))
			if err != nil {
				return c, err
			}
		case "parent":
			parent, err := parseHash(string(value))
			if err != nil {
				return c, err
			}
			c.parents = append(c.parents, parent)
		case "author":
			parseAuthor(string(value), &c.appearance)
		}
	}
	if c.tree == (hash{}) {
		return c, errors.New("commit has no tree")
	}
	return c, nil
}

func parseAuthor(value string, a *Appearance) {
	lt, gt := strings.LastIndexByte(value, '<'), strings.LastIndexByte(value, '>')
	if lt < 0 || gt < lt {
		return
	}
	a.AuthorName = strings.TrimSpace(value[:lt])
	a.AuthorEmail = value[lt+1 : gt]
	fields := strings.Fields(value[gt+1:])
	if len(fields) > 0 {
		if sec, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
			a.AuthorTime = time.Unix(sec, 0)
		}
	}
}

func tagTarget(data []byte) (hash, error) {
	line, _, _ := bytes.Cut(data, []byte{'\n'})
	if !bytes.HasPrefix(line, []byte("object ")) {
		return hash{}, errors.New("tag has no target")
	}
	return parseHash(string(line[7:]))
}

func (s *store) visitTree(ctx context.Context, id hash, prefix string, appearance Appearance, seenTrees map[hash]bool, blobs map[hash]Appearance) error {
	if seenTrees[id] {
		return nil
	}
	seenTrees[id] = true
	obj, err := s.load(id)
	if err != nil {
		return err
	}
	if obj.typ != 2 {
		return errors.New("tree id is not a tree")
	}
	for data := obj.data; len(data) > 0; {
		space := bytes.IndexByte(data, ' ')
		nul := bytes.IndexByte(data, 0)
		if space < 1 || nul < space || nul+21 > len(data) {
			return errors.New("invalid tree object")
		}
		mode, name := string(data[:space]), string(data[space+1:nul])
		var child hash
		copy(child[:], data[nul+1:nul+21])
		data = data[nul+21:]
		path := name
		if prefix != "" {
			path = prefix + "/" + name
		}
		if mode == "40000" || mode == "040000" {
			if err := s.visitTree(ctx, child, path, appearance, seenTrees, blobs); err != nil {
				return err
			}
		} else if mode == "100644" || mode == "100755" {
			if _, ok := blobs[child]; !ok {
				a := appearance
				a.Path = path
				blobs[child] = a
			}
		}
	}
	return ctx.Err()
}

func (s *store) references() ([]hash, error) {
	set := make(map[hash]bool)
	add := func(data []byte) {
		fields := bytes.Fields(data)
		if len(fields) > 0 && len(fields[0]) == 40 {
			if h, err := parseHash(string(fields[0])); err == nil {
				set[h] = true
			}
		}
	}
	if data, err := os.ReadFile(filepath.Join(s.gitDir, "packed-refs")); err == nil {
		for _, line := range bytes.Split(data, []byte{'\n'}) {
			if len(line) > 0 && line[0] != '#' && line[0] != '^' {
				add(line)
			}
		}
	}
	if data, err := os.ReadFile(filepath.Join(s.headDir, "HEAD")); err == nil {
		add(data)
	}
	_ = filepath.WalkDir(filepath.Join(s.gitDir, "refs"), func(path string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if data, readErr := os.ReadFile(path); readErr == nil {
				add(data)
			}
		}
		return nil
	})
	tips := make([]hash, 0, len(set))
	for h := range set {
		tips = append(tips, h)
	}
	return tips, nil
}

func findGitDir(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	for {
		dotGit := filepath.Join(path, ".git")
		if info, err := os.Stat(dotGit); err == nil && info.IsDir() {
			return dotGit, nil
		}
		if data, err := os.ReadFile(dotGit); err == nil {
			value, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "gitdir:")
			if !ok {
				return "", errors.New("invalid .git file")
			}
			gitDir := strings.TrimSpace(value)
			if !filepath.IsAbs(gitDir) {
				gitDir = filepath.Join(path, gitDir)
			}
			return filepath.Clean(gitDir), nil
		}
		if _, err := os.Stat(filepath.Join(path, "objects")); err == nil {
			return path, nil
		}
		parent := filepath.Dir(path)
		if parent == path {
			return "", errors.New("repository not found")
		}
		path = parent
	}
}
