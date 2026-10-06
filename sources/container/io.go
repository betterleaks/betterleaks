package container

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

type contextReader struct {
	ctx context.Context
	io.Reader
}

// budgetReader bounds bytes actually consumed, including data outside tar
// entries. It probes at most one extra byte to distinguish an exact fit from
// an exceeded limit, and keeps the failure visible to subsequent reads.
type budgetReader struct {
	reader    io.Reader
	remaining int64
	limitErr  error
	err       error
}

func (r *budgetReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		var probe [1]byte
		n, err := r.reader.Read(probe[:])
		if n > 0 {
			err = r.limitErr
		}
		r.err = err
		return 0, err
	}
	n, err := r.reader.Read(p[:min(int64(len(p)), r.remaining)])
	r.remaining -= int64(n)
	r.err = err
	return n, err
}

const maxLayerPadding = 16 << 20

// A tar may have record padding after its end marker. Validate that padding
// while reaching the compression trailer and digest; never expand an arbitrary
// tail indefinitely just to verify a checksum.
func drainLayerTail(ctx context.Context, reader io.Reader) error {
	limited := &budgetReader{
		reader:    contextReader{ctx, reader},
		remaining: maxLayerPadding,
		limitErr:  errors.New("layer tar padding exceeds 16 MiB"),
	}
	_, err := io.Copy(zeroPaddingWriter{}, limited)
	return err
}

type zeroPaddingWriter struct{}

func (zeroPaddingWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		if b != 0 {
			return 0, errors.New("nonzero data after layer tar end marker")
		}
	}
	return len(p), nil
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

type verifiedReader struct {
	io.Reader
	hash     hash.Hash
	expected string
	done     bool
	err      error
}

func (r *verifiedReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.Reader.Read(p)
	_, _ = r.hash.Write(p[:n])
	if err == io.EOF && !r.done {
		r.done = true
		if hex.EncodeToString(r.hash.Sum(nil)) != r.expected {
			err = errors.New("container blob digest mismatch")
		}
	}
	if err != nil && err != io.EOF {
		r.err = err
	}
	return n, err
}

// descriptorReader verifies both independent claims in an OCI descriptor.
// Enforce the length while reading so a false declaration cannot bypass a
// caller's admission limit. Sticky errors survive readers that consume n > 0
// bytes and defer inspecting the accompanying error until their next Read.
func descriptorReader(reader io.Reader, d v1.Descriptor) (io.Reader, error) {
	if d.Size < 0 {
		return nil, errors.New("negative container blob size")
	}
	return verifyingReader(&sizedReader{reader: reader, remaining: d.Size}, d.Digest)
}

type sizedReader struct {
	reader    io.Reader
	remaining int64
	err       error
}

func (r *sizedReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		var probe [1]byte
		n, err := r.reader.Read(probe[:])
		if n > 0 {
			err = errors.New("container blob size mismatch: longer than descriptor")
		}
		r.err = err
		return 0, err
	}
	p = p[:min(int64(len(p)), r.remaining)]
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	if err == io.EOF && r.remaining != 0 {
		err = errors.New("container blob size mismatch: shorter than descriptor")
	}
	r.err = err
	return n, err
}
func verifyingReader(reader io.Reader, digest v1.Hash) (io.Reader, error) {
	if digest.Hex == "" {
		return reader, nil
	}
	var h hash.Hash
	switch digest.Algorithm {
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	default:
		return nil, fmt.Errorf("unsupported digest algorithm %q", digest.Algorithm)
	}
	decoded, err := hex.DecodeString(digest.Hex)
	if err != nil || len(decoded) != h.Size() {
		return nil, errors.New("invalid container digest")
	}
	return &verifiedReader{Reader: reader, hash: h, expected: digest.Hex}, nil
}
func checkDigest(raw []byte, digest v1.Hash) error {
	r, err := verifyingReader(bytes.NewReader(raw), digest)
	if err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, r)
	return err
}
func readBlob(ctx context.Context, store imageStore, d v1.Descriptor, limit int64) ([]byte, error) {
	if d.Digest.Hex == "" {
		return nil, errors.New("missing blob digest")
	}
	if d.Size > limit {
		return nil, errors.New("blob exceeds metadata size limit")
	}
	r, err := store.blob(d)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	v, err := descriptorReader(contextReader{ctx, r}, d)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(v, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("blob exceeds metadata size limit")
	}
	return data, nil
}

// decompress detects supported encodings by magic, independent of filename.
// Its Close releases the decoder, but the caller owns the underlying stream.
func decompress(reader io.Reader) (io.ReadCloser, error) {
	b := bufio.NewReader(reader)
	magic, _ := b.Peek(6)
	switch {
	case bytes.HasPrefix(magic, []byte{0x1f, 0x8b}):
		return gzip.NewReader(b)
	case bytes.HasPrefix(magic, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		d, err := zstd.NewReader(b, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(256<<20))
		if err != nil {
			return nil, err
		}
		return d.IOReadCloser(), nil
	case bytes.HasPrefix(magic, []byte("BZh")):
		return io.NopCloser(bzip2.NewReader(b)), nil
	case bytes.HasPrefix(magic, []byte{0xfd, '7', 'z', 'X', 'Z', 0}):
		d, err := xz.NewReader(b)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(d), nil
	default:
		return io.NopCloser(b), nil
	}
}
