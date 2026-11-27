package gitobj

import (
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/require"
)

type sizedObject struct {
	EncodedObject
	id   Hash
	size int64
}

func (o sizedObject) Hash() Hash  { return o.id }
func (o sizedObject) Size() int64 { return o.size }

func cachedID(n int) Hash { return NewHash(fmt.Sprintf("%040x", n+1)) }

func TestObjectCachePrefersCostlyObjects(t *testing.T) {
	c := NewObjectCache(300)
	cheap, costly := sizedObject{EncodedObject: nil, id: cachedID(0), size: 100}, sizedObject{EncodedObject: nil, id: cachedID(1), size: 100}
	c.Put(cheap, 100)
	c.Put(costly, 10_000)
	c.Put(sizedObject{EncodedObject: nil, id: cachedID(2), size: 100}, 5_000)
	// The cheapest object to rebuild goes first, though it is not the oldest.
	c.Put(sizedObject{EncodedObject: nil, id: cachedID(3), size: 100}, 5_000)
	_, ok := c.Get(cheap.id)
	require.False(t, ok)
	_, ok = c.Get(costly.id)
	require.True(t, ok)
	// Each eviction advances the clock, so unused entries eventually age out.
	for i := 4; i < 400; i++ {
		c.Put(sizedObject{EncodedObject: nil, id: cachedID(i), size: 100}, 5_000)
	}
	_, ok = c.Get(costly.id)
	require.False(t, ok)
	require.LessOrEqual(t, c.bytes, c.MaxSize)
	c.Clear()
	_, ok = c.Get(cachedID(399))
	require.False(t, ok)
	require.Empty(t, c.queue)
}

// referenceCache evicts by scanning for the lowest priority.
type referenceCache struct {
	max, bytes int64
	clock      float64
	entries    map[Hash]*cacheEntry
}

func (r *referenceCache) get(id Hash) bool {
	e := r.entries[id]
	if e != nil {
		e.priority = r.clock + e.value
	}
	return e != nil
}

func (r *referenceCache) put(id Hash, size int64, work float64) {
	if size > r.max {
		return
	}
	if r.get(id) {
		return
	}
	value := work / float64(max(size, 1))
	r.entries[id] = &cacheEntry{id: id, object: nil, size: FileSize(size), value: value, priority: r.clock + value}
	r.bytes += size
	for r.bytes > r.max {
		var lowest *cacheEntry
		for _, e := range r.entries {
			if lowest == nil || e.priority < lowest.priority {
				lowest = e
			}
		}
		r.clock = lowest.priority
		r.bytes -= int64(lowest.size)
		delete(r.entries, lowest.id)
	}
}

func TestObjectCacheMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 6))
	c := NewObjectCache(4096)
	ref := &referenceCache{max: 4096, bytes: 0, clock: 0, entries: map[Hash]*cacheEntry{}}
	sizes := map[int]int64{}
	for range 20_000 {
		n := rng.IntN(300)
		id := cachedID(n)
		if rng.IntN(3) == 0 {
			_, got := c.Get(id)
			require.Equal(t, ref.get(id), got)
			continue
		}
		if sizes[n] == 0 {
			sizes[n] = 1 + rng.Int64N(600)
		}
		// Distinct random costs keep priorities from tying.
		work := rng.Float64() * 100_000
		c.Put(sizedObject{EncodedObject: nil, id: id, size: sizes[n]}, work)
		ref.put(id, sizes[n], work)
		require.Len(t, c.entries, len(ref.entries))
		require.Equal(t, ref.bytes, int64(c.bytes))
		for id := range ref.entries {
			require.Contains(t, c.entries, id)
		}
	}
	require.Len(t, c.queue, len(c.entries))
}
