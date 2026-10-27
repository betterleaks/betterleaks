//nolint:exhaustruct // Index tables and iterator positions are initialized incrementally.
package gitobj

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
)

type ReadAtCloser interface {
	io.ReaderAt
	io.Seeker
	io.Closer
}

// Index reads v2 pack indexes without retaining their object tables on the Go
// heap. The reverse index is optional: old repositories get a compact uint32
// permutation on the first OFS lookup, rather than a map of full object IDs.
type Index struct {
	ctx                      context.Context
	idx, rev                 ReadAtCloser
	id                       Hash
	count                    uint32
	fanout                   [256]uint32
	offsets, large, largeEnd int64
	once                     sync.Once
	order                    []uint32
	err                      error
}

func OpenIndex(ctx context.Context, idx, rev ReadAtCloser, id Hash) (*Index, error) {
	i := &Index{ctx: ctx, idx: idx, rev: rev, id: id}
	var header [1032]byte
	if _, err := idx.ReadAt(header[:], 0); err != nil {
		return nil, err
	}
	if !bytes.Equal(header[:4], []byte{255, 't', 'O', 'c'}) || binary.BigEndian.Uint32(header[4:8]) != 2 {
		return nil, errors.New("unsupported Git pack index")
	}
	for n := range i.fanout {
		i.fanout[n] = binary.BigEndian.Uint32(header[8+n*4:])
		if n > 0 && i.fanout[n] < i.fanout[n-1] {
			return nil, errors.New("invalid Git index fanout")
		}
	}
	i.count = i.fanout[255]
	i.offsets = 1032 + int64(i.count)*int64(id.Size()+4)
	i.large = i.offsets + int64(i.count)*4
	size, err := idx.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	i.largeEnd = size - int64(id.Size()*2)
	if i.largeEnd < i.large || (i.largeEnd-i.large)%8 != 0 {
		return nil, errors.New("invalid Git index size")
	}
	var checksum [32]byte
	if _, err := idx.ReadAt(checksum[:id.Size()], i.largeEnd); err != nil {
		return nil, err
	}
	if id.Compare(checksum[:id.Size()]) != 0 {
		return nil, errors.New("git index pack checksum mismatch")
	}
	if rev != nil {
		var header [12]byte
		if _, err := rev.ReadAt(header[:], 0); err != nil {
			return nil, err
		}
		algo := uint32(1)
		if id.Size() == 32 {
			algo = 2
		}
		if string(header[:4]) != "RIDX" || binary.BigEndian.Uint32(header[4:8]) != 1 || binary.BigEndian.Uint32(header[8:]) != algo {
			return nil, errors.New("invalid Git reverse index header")
		}
		size, err := rev.Seek(0, io.SeekEnd)
		if err != nil {
			return nil, err
		}
		end := 12 + int64(i.count)*4
		if size != end+int64(id.Size()*2) {
			return nil, errors.New("invalid Git reverse index size")
		}
		if _, err := rev.ReadAt(checksum[:id.Size()], end); err != nil {
			return nil, err
		}
		if id.Compare(checksum[:id.Size()]) != 0 {
			return nil, errors.New("git reverse index pack checksum mismatch")
		}
	}
	return i, nil
}

func (i *Index) Count() (int64, error) { return int64(i.count), nil }
func (i *Index) Close() error {
	err := i.idx.Close()
	if i.rev != nil {
		err = errors.Join(err, i.rev.Close())
	}
	return err
}
func (i *Index) hash(n uint32) (Hash, error) {
	if n >= i.count {
		return Hash{}, errors.New("git index position out of bounds")
	}
	id := i.id
	id.data = [32]byte{}
	_, err := i.idx.ReadAt(id.data[:id.Size()], 1032+int64(n)*int64(id.Size()))
	return id, err
}
func (i *Index) offset(n uint32) (int64, error) {
	var b [8]byte
	return i.readOffset(n, b[:])
}

func (i *Index) readOffset(n uint32, b []byte) (int64, error) {
	if n >= i.count {
		return 0, errors.New("git index position out of bounds")
	}
	if _, err := i.idx.ReadAt(b[:4], i.offsets+int64(n)*4); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint32(b[:4])
	if v&0x80000000 == 0 {
		return int64(v), nil
	}
	off := i.large + int64(v&0x7fffffff)*8
	if off+8 > i.largeEnd {
		return 0, errors.New("git large offset out of bounds")
	}
	if _, err := i.idx.ReadAt(b[:], off); err != nil {
		return 0, err
	}
	n64 := binary.BigEndian.Uint64(b[:])
	if n64 > math.MaxInt64 {
		return 0, errors.New("git pack offset overflow")
	}
	return int64(n64), nil
}
func (i *Index) FindOffset(id Hash) (int64, error) {
	if id.Size() != i.id.Size() {
		return 0, ErrObjectNotFound
	}
	lo := uint32(0)
	if id.data[0] > 0 {
		lo = i.fanout[id.data[0]-1]
	}
	hi := i.fanout[id.data[0]]
	// Reuse one scratch buffer across the search. Passing a fresh Hash to
	// ReaderAt at each step would allocate once per comparison on the heap.
	var buf [32]byte
	for lo < hi {
		mid := lo + (hi-lo)/2
		if _, err := i.idx.ReadAt(buf[:id.Size()], 1032+int64(mid)*int64(id.Size())); err != nil {
			return 0, err
		}
		switch c := bytes.Compare(buf[:id.Size()], id.data[:id.Size()]); {
		case c < 0:
			lo = mid + 1
		case c > 0:
			hi = mid
		default:
			return i.offset(mid)
		}
	}
	return 0, ErrObjectNotFound
}
func (i *Index) reverse(n uint32, b []byte) (uint32, error) {
	if i.rev != nil {
		_, err := i.rev.ReadAt(b[:4], 12+int64(n)*4)
		return binary.BigEndian.Uint32(b[:]), err
	}
	i.once.Do(func() { i.err = i.buildReverse() })
	if i.err != nil {
		return 0, i.err
	}
	return i.order[n], nil
}

// Radix sorting bounds missing-.rev startup to a fixed number of linear
// passes. Only the uint32 permutation survives; temporary storage costs four
// bytes per object. Check cancellation throughout, including before allocation.
func (i *Index) buildReverse() error {
	if err := i.ctx.Err(); err != nil {
		return err
	}
	order := make([]uint32, i.count)
	for n := range order {
		order[n] = uint32(n)
	}
	scratch := make([]uint32, len(order))
	var buf [8]byte
	passes := 4
	if i.largeEnd > i.large {
		passes = 8
	}
	for pass := range passes {
		var counts [256]uint32
		for n, pos := range order {
			if n%4096 == 0 {
				if err := i.ctx.Err(); err != nil {
					return err
				}
			}
			off, err := i.readOffset(pos, buf[:])
			if err != nil {
				return err
			}
			counts[byte(uint64(off)>>(pass*8))]++
		}
		var next [256]uint32
		for n := 1; n < len(next); n++ {
			next[n] = next[n-1] + counts[n-1]
		}
		for n, pos := range order {
			if n%4096 == 0 {
				if err := i.ctx.Err(); err != nil {
					return err
				}
			}
			off, err := i.readOffset(pos, buf[:])
			if err != nil {
				return err
			}
			key := byte(uint64(off) >> (pass * 8))
			scratch[next[key]] = pos
			next[key]++
		}
		order, scratch = scratch, order
	}
	i.order = order
	return nil
}
func (i *Index) FindHash(off int64) (Hash, error) {
	lo, hi := uint32(0), i.count
	var buf [8]byte
	for lo < hi {
		mid := lo + (hi-lo)/2
		n, err := i.reverse(mid, buf[:])
		if err != nil {
			return Hash{}, err
		}
		pos, err := i.readOffset(n, buf[:])
		if err != nil {
			return Hash{}, err
		}
		if pos < off {
			lo = mid + 1
		} else if pos > off {
			hi = mid
		} else {
			return i.hash(n)
		}
	}
	return Hash{}, ErrObjectNotFound
}

type IndexEntry struct {
	Hash   Hash
	Offset uint64
}
type IndexIter struct {
	index *Index
	pos   uint32
}

func (i *Index) Entries() (*IndexIter, error) { return &IndexIter{index: i}, nil }
func (*IndexIter) Close() error               { return nil }
func (it *IndexIter) Next() (*IndexEntry, error) {
	if it.pos == it.index.count {
		return nil, io.EOF
	}
	h, err := it.index.hash(it.pos)
	if err != nil {
		return nil, err
	}
	off, err := it.index.offset(it.pos)
	if err != nil {
		return nil, err
	}
	it.pos++
	return &IndexEntry{h, uint64(off)}, nil
}

func (i *Index) HashesWithPrefix(prefix []byte) ([]Hash, error) {
	lo, hi := uint32(0), i.count
	if len(prefix) > i.id.Size() {
		return nil, fmt.Errorf("git hash prefix too long")
	}
	if len(prefix) > 0 {
		if prefix[0] > 0 {
			lo = i.fanout[prefix[0]-1]
		}
		hi = i.fanout[prefix[0]]
	}
	var ids []Hash
	for n := lo; n < hi; n++ {
		if n%4096 == 0 {
			if err := i.ctx.Err(); err != nil {
				return nil, err
			}
		}
		h, err := i.hash(n)
		if err != nil {
			return nil, err
		}
		if bytes.HasPrefix(h.Bytes(), prefix) {
			ids = append(ids, h)
		}
	}
	return ids, nil
}

// ForEachHashWithPrefix visits matching IDs without allocating a result set.
// prefix is hexadecimal and may end in a half-byte. Returning false stops the
// walk, allowing revision lookup to stop as soon as ambiguity is established.
func (i *Index) ForEachHashWithPrefix(prefix string, yield func(Hash) bool) error {
	if err := i.ctx.Err(); err != nil {
		return err
	}
	if len(prefix) == 0 || len(prefix) > i.id.Size()*2 {
		return errors.New("invalid git hash prefix length")
	}
	whole, odd := len(prefix)/2, len(prefix)%2 != 0
	if odd {
		prefix += "0"
	}
	first := Hash{sha256: i.id.sha256}
	if _, err := hex.Decode(first.data[:], []byte(prefix)); err != nil {
		return err
	}
	low, high := first.data[0], first.data[0]
	if whole == 0 {
		high |= 0x0f
	}
	lo, hi := uint32(0), i.fanout[high]
	if low > 0 {
		lo = i.fanout[low-1]
	}
	// The index is sorted by object ID. Seek directly to the first possible
	// match, including all bits of an odd-length prefix.
	var buf [32]byte
	end := hi
	for lo < hi {
		mid := lo + (hi-lo)/2
		if _, err := i.idx.ReadAt(buf[:i.id.Size()], 1032+int64(mid)*int64(i.id.Size())); err != nil {
			return err
		}
		if bytes.Compare(buf[:i.id.Size()], first.data[:i.id.Size()]) < 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	for n := lo; n < end; n++ {
		if err := i.ctx.Err(); err != nil {
			return err
		}
		id, err := i.hash(n)
		if err != nil {
			return err
		}
		if !bytes.Equal(id.data[:whole], first.data[:whole]) || odd && id.data[whole]&0xf0 != first.data[whole] {
			break
		}
		if !yield(id) {
			break
		}
	}
	return nil
}
