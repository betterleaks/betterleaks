package gitobj

import "sync"

type FileSize int64

// ObjectCache is a byte-bounded GreedyDual-Size cache. An entry's priority is
// the cache clock at its last use plus the work rebuilding it would take per
// byte it occupies. Eviction removes the lowest priority and advances the
// clock to it, so stale entries age out while, among entries used about as
// recently, those that are cheap to rebuild for their size go first.
type ObjectCache struct {
	MaxSize FileSize
	mu      sync.Mutex
	bytes   FileSize
	clock   float64
	// queue is a binary min-heap on each entry's priority when it was last
	// placed there. Uses raise priorities without reordering; eviction
	// requeues an entry whose key has gone stale.
	queue   []queued
	entries map[Hash]*cacheEntry
}

type queued struct {
	key   float64
	entry *cacheEntry
}

type cacheEntry struct {
	id       Hash
	object   EncodedObject
	size     FileSize
	value    float64 // rebuild work per byte
	priority float64
}

func NewObjectCache(n FileSize) *ObjectCache {
	return &ObjectCache{MaxSize: n, entries: make(map[Hash]*cacheEntry)} //nolint:exhaustruct // Cache and mutex start empty.
}

func (c *ObjectCache) Get(id Hash) (EncodedObject, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[id]; e != nil {
		e.priority = c.clock + e.value
		return e.object, true
	}
	return nil, false
}

// Put caches o, whose contents would take work to rebuild.
func (c *ObjectCache) Put(o EncodedObject, work float64) {
	id, size := o.Hash(), FileSize(o.Size())
	if size < 0 || size > c.MaxSize {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[id]; e != nil {
		e.priority = c.clock + e.value
		return
	}
	value := work / float64(max(size, 1))
	e := &cacheEntry{id: id, object: o, size: size, value: value, priority: c.clock + value}
	c.entries[id] = e
	c.queue = append(c.queue, queued{e.priority, e})
	c.up(len(c.queue) - 1)
	c.bytes += size
	for c.bytes > c.MaxSize {
		top := &c.queue[0]
		e := top.entry
		if top.key < e.priority {
			top.key = e.priority
			c.down(0)
			continue
		}
		last := len(c.queue) - 1
		c.queue[0], c.queue[last] = c.queue[last], queued{key: 0, entry: nil}
		c.queue = c.queue[:last]
		c.down(0)
		c.clock = e.priority
		c.bytes -= e.size
		delete(c.entries, e.id)
	}
}

func (c *ObjectCache) up(i int) {
	q := c.queue
	x := q[i]
	for i > 0 {
		parent := (i - 1) / 2
		if q[parent].key <= x.key {
			break
		}
		q[i] = q[parent]
		i = parent
	}
	q[i] = x
}

func (c *ObjectCache) down(i int) {
	q := c.queue
	if i >= len(q) {
		return
	}
	x := q[i]
	for {
		child := 2*i + 1
		if child >= len(q) {
			break
		}
		if right := child + 1; right < len(q) && q[right].key < q[child].key {
			child = right
		}
		if x.key <= q[child].key {
			break
		}
		q[i] = q[child]
		i = child
	}
	q[i] = x
}

func (c *ObjectCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[Hash]*cacheEntry)
	c.queue = nil
	c.bytes = 0
	c.clock = 0
}
