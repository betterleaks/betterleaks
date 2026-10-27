// Package gitobj contains the read-only object model used by the Git scanner.
// Object IDs carry their format so SHA-1 and SHA-256 repositories can be read
// in the same process. Transport and format-independent Git APIs use go-git v5.
//
//nolint:exhaustruct // IDs and memory objects start with zero-filled contents.
package gitobj

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"slices"
	"strconv"

	"github.com/go-git/go-git/v5/plumbing"
	format "github.com/go-git/go-git/v5/plumbing/format/config"
	githash "github.com/go-git/go-git/v5/plumbing/hash"
)

type ObjectType = plumbing.ObjectType
type ObjectFormat = format.ObjectFormat
type ReferenceName = plumbing.ReferenceName
type ReferenceType = plumbing.ReferenceType
type Revision = plumbing.Revision

const (
	SHA1                           = format.SHA1
	SHA256                         = format.SHA256
	SHA256Size                     = 32
	UnsetObjectFormat ObjectFormat = ""
	AnyObject                      = plumbing.AnyObject
	CommitObject                   = plumbing.CommitObject
	TreeObject                     = plumbing.TreeObject
	BlobObject                     = plumbing.BlobObject
	TagObject                      = plumbing.TagObject
	OFSDeltaObject                 = plumbing.OFSDeltaObject
	REFDeltaObject                 = plumbing.REFDeltaObject
	HEAD                           = plumbing.HEAD
	HashReference                  = plumbing.HashReference
	SymbolicReference              = plumbing.SymbolicReference
)

var (
	ZeroHash             Hash
	ErrObjectNotFound    = plumbing.ErrObjectNotFound
	ErrReferenceNotFound = plumbing.ErrReferenceNotFound
)

// Hash is comparable and suitable as a map key. Its zero value is SHA-1.
type Hash struct {
	data   [32]byte
	sha256 bool
}

func NewHash(s string) Hash {
	var h Hash
	if len(s) != 40 && len(s) != 64 {
		return h
	}
	h.sha256 = len(s) == 64
	if _, err := hex.Decode(h.data[:h.Size()], []byte(s)); err != nil {
		return Hash{}
	}
	return h
}

func IsHash(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	var b [32]byte
	_, err := hex.Decode(b[:], []byte(s))
	return err == nil
}

func FromObjectFormat(f ObjectFormat) Hash { return Hash{sha256: f == SHA256} }
func (h Hash) Size() int {
	if h.sha256 {
		return 32
	}
	return 20
}
func (h Hash) Bytes() []byte                { return h.data[:h.Size()] }
func (h Hash) String() string               { return hex.EncodeToString(h.data[:h.Size()]) }
func (h Hash) IsZero() bool                 { return h.data == [32]byte{} }
func (h Hash) Compare(b []byte) int         { return bytes.Compare(h.data[:h.Size()], b) }
func (h *Hash) ResetBySize(n int)           { *h = Hash{sha256: n == 32} }
func (h *Hash) Write(b []byte) (int, error) { return copy(h.data[:h.Size()], b), nil }
func (h *Hash) ReadFrom(r io.Reader) (int64, error) {
	n, err := io.ReadFull(r, h.data[:h.Size()])
	return int64(n), err
}
func HashesSort(h []Hash) { slices.SortFunc(h, func(a, b Hash) int { return a.Compare(b.Bytes()) }) }

func NewChecksum(f ObjectFormat) (hash.Hash, error) {
	switch f {
	case SHA1, UnsetObjectFormat:
		return githash.New(crypto.SHA1), nil
	case SHA256:
		return sha256.New(), nil
	default:
		return nil, fmt.Errorf("unsupported Git object format %q", f)
	}
}

type Hasher struct {
	hash.Hash
	format ObjectFormat
}

func NewHasher(f ObjectFormat, kind ObjectType, size int64) Hasher {
	h, err := NewChecksum(f)
	if err != nil {
		panic(err)
	}
	h.Write(kind.Bytes())
	h.Write([]byte(" " + strconv.FormatInt(size, 10) + "\x00"))
	return Hasher{h, f}
}
func (h Hasher) Sum() Hash {
	id := FromObjectFormat(h.format)
	id.Write(h.Hash.Sum(nil))
	return id
}

type EncodedObject interface {
	Hash() Hash
	Type() ObjectType
	SetType(kind ObjectType)
	Size() int64
	SetSize(size int64)
	Reader() (io.ReadCloser, error)
	Writer() (io.WriteCloser, error)
}
type ObjectReader interface {
	EncodedObject(kind ObjectType, id Hash) (EncodedObject, error)
}

type MemoryObject struct {
	kind ObjectType
	id   Hash
	data bytes.Buffer
}

func NewMemoryObject(id Hash) *MemoryObject { return &MemoryObject{id: id} }
func (o *MemoryObject) Hash() Hash {
	h := NewHasher(o.Format(), o.kind, o.Size())
	h.Write(o.data.Bytes())
	return h.Sum()
}
func (o *MemoryObject) Format() ObjectFormat {
	if o.id.sha256 {
		return SHA256
	}
	return SHA1
}
func (o *MemoryObject) Type() ObjectType     { return o.kind }
func (o *MemoryObject) SetType(t ObjectType) { o.kind = t }
func (o *MemoryObject) Size() int64          { return int64(o.data.Len()) }
func (*MemoryObject) SetSize(int64)          {}
func (o *MemoryObject) Reader() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(o.data.Bytes())), nil
}
func (o *MemoryObject) Writer() (io.WriteCloser, error) { return memoryWriter{&o.data}, nil }

type memoryWriter struct{ io.Writer }

func (memoryWriter) Close() error { return nil }
