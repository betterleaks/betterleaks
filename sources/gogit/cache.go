package gogit

import (
	"container/list"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"

	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/cache"
	"github.com/go-git/go-git/v6/plumbing/format/packfile"
	"github.com/go-git/go-git/v6/plumbing/object"
)

// FSObject.Size reports content size, but its reader closure retains a Packfile
// and scanner buffers. Caching tiny commits this way can turn a 96 MiB cache
// into gigabytes. Keep materialized objects (including reconstructed delta
// bases) and let these storage handles go after each read. Their
// contents would still need decompression on every Reader call, even if cached.
type objectCache struct{ *cache.ObjectLRU }

func (c *objectCache) Put(obj plumbing.EncodedObject) {
	if _, lazy := obj.(*packfile.FSObject); lazy {
		return
	}
	if cache.FileSize(obj.Size()) > c.MaxSize {
		return
	}
	// Upstream's LRU calls Hash while holding its global mutex. Hashing a
	// reconstructed blob can scan megabytes and block every cache lookup.
	// Materialized objects are private to their decoder until this publication;
	// compute their memoized hash before entering the cache's critical section.
	obj.Hash()
	c.ObjectLRU.Put(obj)
}

// Only Entries and Hash are shared. Never call Tree.FindEntry/Tree.Tree on a
// cached tree: those methods can lazily mutate the tree's internal path cache.
// 32 MiB includes an estimate for decoded entries, names, and cache overhead.
type treeCache struct {
	mu      sync.Mutex
	entries map[plumbing.Hash]*list.Element
	lru     list.List
	bytes   int
	r       *git.Repository
}
type cachedTree struct {
	id    plumbing.Hash
	tree  *object.Tree
	bytes int
}

func (c *treeCache) get(id plumbing.Hash) (*object.Tree, error) {
	c.mu.Lock()
	if e := c.entries[id]; e != nil {
		c.lru.MoveToFront(e)
		t := e.Value.(*cachedTree).tree
		c.mu.Unlock()
		return t, nil
	}
	c.mu.Unlock()
	t, err := c.r.TreeObject(id)
	if err != nil {
		return nil, err
	}
	// Count allocated slice capacity, not only its populated entries. Go's
	// append growth can otherwise undercharge large decoded trees substantially.
	size := 256 + cap(t.Entries)*int(reflect.TypeFor[object.TreeEntry]().Size())
	for _, entry := range t.Entries {
		size += (len(entry.Name) + 15) &^ 15
	}
	if size > 8<<20 {
		return t, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[plumbing.Hash]*list.Element)
	}
	if e := c.entries[id]; e != nil {
		c.lru.MoveToFront(e)
		return e.Value.(*cachedTree).tree, nil
	}
	c.entries[id] = c.lru.PushFront(&cachedTree{id, t, size})
	c.bytes += size
	for c.bytes > 32<<20 {
		e := c.lru.Back()
		value := e.Value.(*cachedTree)
		delete(c.entries, value.id)
		c.bytes -= value.bytes
		c.lru.Remove(e)
	}
	return t, nil
}

// Merge commits and branch histories often compare the same pair of blobs.
// Cache only the immutable text additions, never commit/path attributes or
// findings. Each use still passes through the current commit's filtering and
// scanner callback. Archives retain their ordinary streaming path.
type patchCache struct {
	mu      sync.Mutex
	entries map[patchKey]*list.Element
	lru     list.List
	bytes   int
	hits    uint64
	misses  uint64
}

type patchKey struct{ from, to plumbing.Hash }
type textAddition struct {
	raw  string
	line int
}
type cachedPatch struct {
	key       patchKey
	additions []textAddition
	bytes     int
}

const (
	patchCacheBudget = 32 << 20
	maxCachedPatch   = 256 << 10
	patchOverhead    = 384 // Key copies, map slots, list node and cachedPatch.
)

func (c *patchCache) get(key patchKey) ([]textAddition, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[key]; e != nil {
		c.hits++
		c.lru.MoveToFront(e)
		return e.Value.(*cachedPatch).additions, true
	}
	c.misses++
	return nil, false
}

// put takes ownership of additions. Its slice and strings must remain immutable.
func (c *patchCache) put(key patchKey, additions []textAddition) {
	size := patchOverhead + cap(additions)*24
	for _, a := range additions {
		size += (len(a.raw) + 15) &^ 15
	}
	if size > maxCachedPatch {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[patchKey]*list.Element)
	}
	if c.entries[key] != nil {
		return
	}
	c.entries[key] = c.lru.PushFront(&cachedPatch{key, additions, size})
	c.bytes += size
	for c.bytes > patchCacheBudget {
		e := c.lru.Back()
		value := e.Value.(*cachedPatch)
		delete(c.entries, value.key)
		c.bytes -= value.bytes
		c.lru.Remove(e)
	}
}

// diskObjectCache is a bounded, scan-local ring of materialized large objects.
// Deep delta chains can evict their own bases from the RAM cache before the
// next file uses them. Keeping those bases on disk avoids reconstructing the
// same multi-megabyte content dozens of times. Readers own their returned bytes;
// reusing a segment can never change a fragment or an object still in use.
type diskObjectCache struct {
	mu          sync.RWMutex
	file        *os.File
	failed      bool
	segmentSize int64
	segment     int
	used        int64
	entries     map[plumbing.Hash]diskObject
	keys        [8][]plumbing.Hash
}

type diskObject struct {
	offset int64
	size   int64
	kind   plumbing.ObjectType
}

func (c *diskObjectCache) get(id plumbing.Hash) (*storedObject, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[id]
	if !ok {
		return nil, false
	}
	var out strings.Builder
	out.Grow(int(e.size))
	buf := diskReadBuffers.Get().(*[256 << 10]byte)
	defer diskReadBuffers.Put(buf)
	n, err := io.CopyBuffer(&out, io.NewSectionReader(c.file, e.offset, e.size), buf[:])
	if err != nil || n != e.size {
		return nil, false
	}
	return &storedObject{id: id, kind: e.kind, raw: out.String()}, true
}

func (c *diskObjectCache) put(o *storedObject) {
	if c == nil || o.Size() < 1<<20 || o.Size() > c.segmentSize {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed {
		return
	}
	if _, ok := c.entries[o.id]; ok {
		return
	}
	if c.file == nil {
		f, err := os.CreateTemp("", "betterleaks-git-objects-*")
		if err != nil {
			c.failed = true
			return
		}
		c.file = f
		// On Unix, unlink immediately so even an interrupted process releases
		// the cache. Platforms that forbid unlinking an open file use close's
		// removal instead. All cache access uses the existing descriptor.
		_ = os.Remove(f.Name())
		c.entries = make(map[plumbing.Hash]diskObject)
	}
	if c.used+o.Size() > c.segmentSize {
		c.segment = (c.segment + 1) % len(c.keys)
		c.used = 0
		for _, id := range c.keys[c.segment] {
			delete(c.entries, id)
		}
		c.keys[c.segment] = c.keys[c.segment][:0]
	}
	offset := int64(c.segment)*c.segmentSize + c.used
	if _, err := c.file.Seek(offset, io.SeekStart); err != nil {
		c.failed = true
		return
	}
	n, err := c.file.WriteString(o.raw)
	if err != nil || n != len(o.raw) {
		c.failed = true
		return
	}

	c.entries[o.id] = diskObject{offset: offset, size: o.Size(), kind: o.kind}
	c.keys[c.segment] = append(c.keys[c.segment], o.id)
	c.used += o.Size()
}

func (c *diskObjectCache) close() {
	if c == nil || c.file == nil {
		return
	}
	c.file.Close()
	os.Remove(c.file.Name())
}

var diskReadBuffers = sync.Pool{New: func() any { return new([256 << 10]byte) }}
