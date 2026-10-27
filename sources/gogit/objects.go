package gogit

import (
	"bufio"
	"compress/zlib"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"strings"
	"sync"

	"github.com/betterleaks/betterleaks/v2/internal/gitobj"
	"github.com/betterleaks/betterleaks/v2/internal/gitpack"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
)

// objectStorage reads immutable repository objects through the scanner's
// bounded caches and lazy indexes. It owns no writable Git storage and checks
// the scan context before reads and during decompression.
type objectStorage struct {
	fs         readOnlyFS
	cfg        *config.Config
	alternates []readOnlyFS
	refsOnce   sync.Once
	refs       map[gitobj.ReferenceName]*gitobj.Reference
	refsErr    error
	packedOnce sync.Once
	packedRefs map[gitobj.ReferenceName]*gitobj.Reference
	packedErr  error
	objects    *objectCache
	ctx        context.Context
	limit      int64
	packs      []*objectPack
	disk       *diskObjectCache
	shallow    map[gitobj.Hash]struct{}
}

func (s *objectStorage) EncodedObject(kind gitobj.ObjectType, id gitobj.Hash) (gitobj.EncodedObject, error) {
	o, err := s.read(id)
	if err != nil {
		return nil, err
	}
	if kind != gitobj.AnyObject && o.Type() != kind {
		return nil, gitobj.ErrObjectNotFound
	}
	return o, nil
}

// ObjectType follows pack delta bases using only record headers. Revision
// disambiguation must not decompress unrelated blobs or apply their size limit
// just to decide whether they can name a commit.
func (s *objectStorage) ObjectType(id gitobj.Hash) (gitobj.ObjectType, error) {
	if err := s.ctx.Err(); err != nil {
		return gitobj.AnyObject, err
	}
	if cached := s.cached(id); cached != nil {
		return cached.Type(), nil
	}
	pack, offset, err := s.locate(id)
	if err != nil {
		return gitobj.AnyObject, err
	}
	input := packInflaters.Get().(*packInflater)
	defer func() { input.input.Reset(nil); packInflaters.Put(input) }()
	for range maxDeltaChain + 1 {
		if err := s.ctx.Err(); err != nil {
			return gitobj.AnyObject, err
		}
		if pack == nil {
			return s.looseObjectType(id)
		}
		if offset < 12 || offset >= pack.end {
			return gitobj.AnyObject, errors.New("git pack offset out of bounds")
		}
		input.input.Reset(io.NewSectionReader(pack.file, offset, pack.end-offset))
		header, err := gitpack.ReadHeader(input.input, offset, pack.hashSize, math.MaxInt64)
		if err != nil {
			return gitobj.AnyObject, err
		}
		switch header.Type {
		case gitobj.OFSDeltaObject:
			offset = header.BaseOffset
		case gitobj.REFDeltaObject:
			id = header.BaseID
			pack, offset, err = s.locate(id)
			if err != nil {
				return gitobj.AnyObject, err
			}
		default:
			return header.Type, nil
		}
	}
	return gitobj.AnyObject, limitf("git object type delta chain exceeds %d", maxDeltaChain)
}

func (s *objectStorage) looseObjectType(id gitobj.Hash) (gitobj.ObjectType, error) {
	hex := id.String()
	for _, fs := range append([]readOnlyFS{s.fs}, s.alternates...) {
		f, err := fs.Open("objects/" + hex[:2] + "/" + hex[2:])
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return gitobj.AnyObject, err
		}
		kind, err := looseObjectType(contextReader{s.ctx, f})
		return kind, errors.Join(err, f.Close())
	}
	return gitobj.AnyObject, gitobj.ErrObjectNotFound
}

func looseObjectType(r io.Reader) (gitobj.ObjectType, error) {
	z, err := zlib.NewReader(r)
	if err != nil {
		return gitobj.AnyObject, err
	}
	defer z.Close()
	// The longest valid type, "commit", is followed by a space. Do not read
	// the object's body or allocate according to its declared size.
	name, err := bufio.NewReader(io.LimitReader(z, 8)).ReadString(' ')
	if err != nil {
		return gitobj.AnyObject, err
	}
	kind, err := plumbing.ParseObjectType(strings.TrimSuffix(name, " "))
	if err != nil || kind.IsDelta() || kind == gitobj.AnyObject {
		return gitobj.AnyObject, errors.Join(err, errors.New("invalid loose Git object type"))
	}
	return kind, nil
}

// parents returns a commit's parents. Like Git, shallow boundary commits are
// treated as root commits because their parents were never fetched.
func (s *objectStorage) parents(c *gitobj.Commit) []gitobj.Hash {
	if _, ok := s.shallow[c.Hash]; ok {
		return nil
	}
	return c.ParentHashes
}

func (s *objectStorage) read(id gitobj.Hash) (*storedObject, error) {
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

func (s *objectStorage) cached(id gitobj.Hash) *storedObject {
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
// in an alternate, or absent.
func (s *objectStorage) locate(id gitobj.Hash) (*objectPack, int64, error) {
	for _, p := range s.packs {
		offset, err := p.index.FindOffset(id)
		if errors.Is(err, gitobj.ErrObjectNotFound) {
			continue
		}
		return p, offset, err
	}
	return nil, 0, nil
}

// readFallback reads loose objects after the pack indexes have been searched.
func (s *objectStorage) readFallback(id gitobj.Hash) (*storedObject, error) {
	if o := s.cached(id); o != nil {
		return o, nil
	}
	return s.readLoose(id)
}

var objectReadBuffers = sync.Pool{New: func() any { return new([32 << 10]byte) }}

func readObjectString(ctx context.Context, obj gitobj.EncodedObject, limit int64) (string, error) {
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
	id   gitobj.Hash
	kind gitobj.ObjectType
	raw  string
}

func (o *storedObject) Hash() gitobj.Hash       { return o.id }
func (o *storedObject) Type() gitobj.ObjectType { return o.kind }
func (o *storedObject) Size() int64             { return int64(len(o.raw)) }
func (*storedObject) SetType(gitobj.ObjectType) {}
func (*storedObject) SetSize(int64)             {}
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

func (o *storedObject) Text() string { return o.raw }
