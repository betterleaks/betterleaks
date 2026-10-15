package gogit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/go-git/go-git/v6/storage/filesystem"
)

// objectStorage keeps go-git's repository discovery, indexes and loose-object
// support, but materializes deltas directly into immutable strings. The normal
// reader copies the base, builds a temporary result, copies it into MemoryObject,
// then hashes that result before the source copies it into a string again.
//
// go-git's storage interfaces take no context, so the scan's context is held
// here and checked on every read.
type objectStorage struct {
	*filesystem.Storage
	objects *objectCache
	ctx     context.Context
	limit   int64
	packs   []*objectPack
	disk    *diskObjectCache
	shallow map[plumbing.Hash]struct{}
}

func (s *objectStorage) EncodedObject(kind plumbing.ObjectType, id plumbing.Hash) (plumbing.EncodedObject, error) {
	o, err := s.read(id)
	if err != nil {
		return nil, err
	}
	if kind != plumbing.AnyObject && o.Type() != kind {
		return nil, plumbing.ErrObjectNotFound
	}
	return o, nil
}

// parents returns a commit's parents. Like Git, shallow boundary commits are
// treated as root commits because their parents were never fetched.
func (s *objectStorage) parents(c *object.Commit) []plumbing.Hash {
	if _, ok := s.shallow[c.Hash]; ok {
		return nil
	}
	return c.ParentHashes
}

func (s *objectStorage) read(id plumbing.Hash) (*storedObject, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	if o := s.cached(id); o != nil {
		return o, nil
	}
	p, offset, err := s.locate(id)
	if err != nil {
		return nil, err
	}
	if p != nil {
		return s.readPacked(p, offset, id)
	}
	return s.readFallback(id)
}

func (s *objectStorage) cached(id plumbing.Hash) *storedObject {
	if o, ok := s.objects.Get(id); ok {
		if o, ok := o.(*storedObject); ok {
			return o
		}
	}
	return nil
}

func (s *objectStorage) keep(o *storedObject) {
	s.disk.put(o)
	s.objects.Put(o)
}

// locate finds id in the mapped packs. A nil pack means the object is loose,
// in an alternate, or in a pack without a reverse index.
func (s *objectStorage) locate(id plumbing.Hash) (*objectPack, int64, error) {
	for _, p := range s.packs {
		offset, err := p.index.FindOffset(id)
		if errors.Is(err, plumbing.ErrObjectNotFound) {
			continue
		}
		return p, offset, err
	}
	return nil, 0, nil
}

// readFallback uses upstream's reader for loose objects, alternates and packs
// without a reverse index. DeltaObject probes loose files even for every packed
// delta base, which is substantially slower than the mapped pack path.
func (s *objectStorage) readFallback(id plumbing.Hash) (*storedObject, error) {
	if o := s.cached(id); o != nil {
		return o, nil
	}
	o, err := s.Storage.EncodedObject(plumbing.AnyObject, id)
	if err != nil {
		return nil, err
	}
	raw, err := readObjectString(s.ctx, o, s.limit)
	if err != nil {
		return nil, fmt.Errorf("object %s: %w", id, err)
	}
	result := &storedObject{id: id, kind: o.Type(), raw: raw}
	s.objects.Put(result)
	return result, nil
}

var objectReadBuffers = sync.Pool{New: func() any { return new([32 << 10]byte) }}

func readObjectString(ctx context.Context, obj plumbing.EncodedObject, limit int64) (string, error) {
	if obj.Size() < 0 {
		return "", errors.New("negative git object size")
	}
	if obj.Size() > limit {
		return "", limitf("object size %d exceeds reconstruction limit %d", obj.Size(), limit)
	}
	r, err := obj.Reader()
	if err != nil {
		return "", err
	}
	defer r.Close()
	var b strings.Builder
	b.Grow(int(obj.Size()))
	buf := objectReadBuffers.Get().(*[32 << 10]byte)
	defer objectReadBuffers.Put(buf)
	_, err = io.CopyBuffer(&b, io.LimitReader(contextReader{ctx, r}, obj.Size()+1), buf[:])
	if err != nil {
		return "", err
	}
	if int64(b.Len()) != obj.Size() {
		return "", errors.New("git object size mismatch")
	}
	return b.String(), nil
}

type storedObject struct {
	id   plumbing.Hash
	kind plumbing.ObjectType
	raw  string
}

func (o *storedObject) Hash() plumbing.Hash       { return o.id }
func (o *storedObject) Type() plumbing.ObjectType { return o.kind }
func (o *storedObject) Size() int64               { return int64(len(o.raw)) }
func (*storedObject) SetType(plumbing.ObjectType) {}
func (*storedObject) SetSize(int64)               {}
func (o *storedObject) Reader() (io.ReadCloser, error) {
	return objectStringReader{strings.NewReader(o.raw)}, nil
}
func (*storedObject) Writer() (io.WriteCloser, error) {
	return nil, errors.New("cached git object is read-only")
}

// Preserve io.Seeker for go-git delta decoding; io.NopCloser would hide it.
type objectStringReader struct{ *strings.Reader }

func (objectStringReader) Close() error { return nil }

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}
