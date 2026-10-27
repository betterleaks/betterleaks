package gitpack

import (
	"errors"
	"fmt"
	"io"

	"github.com/betterleaks/betterleaks/v2/internal/gitobj"
)

// Header describes one packed record. Size is the inflated record size; for a
// delta it measures the instruction stream, not the reconstructed object.
type Header struct {
	Type       gitobj.ObjectType
	Size       int64
	BaseOffset int64
	BaseID     gitobj.Hash
}

// ReadHeader validates sizes and OFS distances before callers inflate or allocate.
func ReadHeader(r interface {
	io.Reader
	io.ByteReader
}, offset int64, hashSize int, limit int64) (Header, error) {
	var h Header
	if offset < 12 || (hashSize != 20 && hashSize != 32) || limit < 0 {
		return h, errors.New("invalid Git pack header parameters")
	}
	limit = min(limit, int64(int(^uint(0)>>1)))
	b, err := r.ReadByte()
	if err != nil {
		return h, err
	}
	h.Type = gitobj.ObjectType((b >> 4) & 7)
	if !h.Type.Valid() {
		return h, errors.New("invalid Git pack object type")
	}
	size := uint64(b & 15)
	for shift := uint(4); b&128 != 0; shift += 7 {
		if shift >= 63 {
			return h, errors.New("git pack object size overflow")
		}
		if b, err = r.ReadByte(); err != nil {
			return h, err
		}
		if uint64(b&127) > uint64(limit)>>shift {
			return h, fmt.Errorf("%w: packed object exceeds reconstruction limit %d", ErrLimit, limit)
		}
		size |= uint64(b&127) << shift
	}
	if size > uint64(limit) {
		return h, fmt.Errorf("%w: packed object size %d exceeds reconstruction limit %d", ErrLimit, size, limit)
	}
	h.Size = int64(size)
	switch h.Type {
	case gitobj.OFSDeltaObject:
		if b, err = r.ReadByte(); err != nil {
			return h, err
		}
		distance := uint64(b & 127)
		for b&128 != 0 {
			if distance+1 > uint64(offset)>>7 {
				return h, errors.New("git delta offset out of bounds")
			}
			if b, err = r.ReadByte(); err != nil {
				return h, err
			}
			distance = ((distance + 1) << 7) | uint64(b&127)
		}
		if distance == 0 || distance > uint64(offset-12) {
			return h, errors.New("git delta offset out of bounds")
		}
		h.BaseOffset = offset - int64(distance)
	case gitobj.REFDeltaObject:
		h.BaseID.ResetBySize(hashSize)
		_, err = h.BaseID.ReadFrom(r)
	}
	return h, err
}
