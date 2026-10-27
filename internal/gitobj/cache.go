package gitobj

import (
	"container/list"
	"sync"
)

type FileSize int64
type ObjectLRU struct {
	MaxSize FileSize
	mu      sync.Mutex
	bytes   FileSize
	lru     list.List
	entries map[Hash]*list.Element
}
type cachedObject struct {
	id     Hash
	object EncodedObject
	size   FileSize
}

func NewObjectLRU(n FileSize) *ObjectLRU {
	return &ObjectLRU{MaxSize: n, entries: make(map[Hash]*list.Element)} //nolint:exhaustruct // Cache and mutex start empty.
}
func (c *ObjectLRU) Get(id Hash) (EncodedObject, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[id]; e != nil {
		c.lru.MoveToFront(e)
		return e.Value.(cachedObject).object, true
	}
	return nil, false
}
func (c *ObjectLRU) Put(o EncodedObject) {
	id, size := o.Hash(), FileSize(o.Size())
	if size < 0 || size > c.MaxSize {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[id]; e != nil {
		c.lru.MoveToFront(e)
		return
	}
	c.entries[id] = c.lru.PushFront(cachedObject{id, o, size})
	c.bytes += size
	for c.bytes > c.MaxSize {
		e := c.lru.Back()
		v := e.Value.(cachedObject)
		c.bytes -= v.size
		delete(c.entries, v.id)
		c.lru.Remove(e)
	}
}
func (c *ObjectLRU) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[Hash]*list.Element)
	c.bytes = 0
	c.lru.Init()
}
