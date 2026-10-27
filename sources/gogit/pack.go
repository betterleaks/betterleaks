package gogit

import (
	"bufio"
	"compress/zlib"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/betterleaks/betterleaks/v2/internal/gitobj"
	"github.com/betterleaks/betterleaks/v2/internal/gitpack"
)

type objectPack struct {
	index *gitobj.Index
	file  interface {
		io.ReaderAt
		io.Closer
	}
	end      int64
	hashSize int
}

func (s *objectStorage) openPacks(fs readOnlyFS) error {
	for _, fs := range append([]readOnlyFS{fs}, s.alternates...) {
		entries, err := fs.ReadDir("objects/pack")
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := s.ctx.Err(); err != nil {
				return err
			}
			name := entry.Name()
			if !strings.HasPrefix(name, "pack-") || !strings.HasSuffix(name, ".idx") {
				continue
			}
			hex := strings.TrimSuffix(strings.TrimPrefix(name, "pack-"), ".idx")
			if !gitobj.IsHash(hex) || len(hex) != gitobj.FromObjectFormat(s.cfg.Extensions.ObjectFormat).Size()*2 {
				return errors.New("invalid pack filename")
			}
			id := gitobj.NewHash(hex)
			path := "objects/pack/pack-" + hex
			idx, err := fs.Open(path + ".idx")
			if err != nil {
				return err
			}
			rev, err := fs.Open(path + ".rev")
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				idx.Close()
				return err
			}
			index, err := gitobj.OpenIndex(s.ctx, idx, rev, id)
			if err != nil {
				idx.Close()
				if rev != nil {
					rev.Close()
				}
				return err
			}

			f, err := fs.Open(path + ".pack")
			if err != nil {
				index.Close()
				return err
			}
			end, err := f.Seek(0, io.SeekEnd)
			if err != nil {
				f.Close()
				index.Close()
				return err
			}
			p := &objectPack{index: index, file: f, end: end - int64(id.Size()), hashSize: id.Size()}
			s.packs = append(s.packs, p)
			var header [12]byte
			if _, err := f.ReadAt(header[:], 0); err != nil {
				return err
			}
			version := binary.BigEndian.Uint32(header[4:8])
			if string(header[:4]) != "PACK" || (version != 2 && version != 3) {
				return errors.New("invalid git pack header")
			}
			count, err := index.Count()
			if err != nil {
				return err
			}
			if int64(binary.BigEndian.Uint32(header[8:])) != count {
				return errors.New("git pack/index object count mismatch")
			}
			var footer [32]byte
			if _, err := f.ReadAt(footer[:id.Size()], p.end); err != nil {
				return err
			}
			if id.Compare(footer[:id.Size()]) != 0 {
				return errors.New("git pack/index checksum mismatch")
			}
		}
	}
	return nil
}

func (s *objectStorage) closePacks() {
	s.disk.close()
	for _, p := range s.packs {
		p.index.Close()
		p.file.Close()
	}
	s.packs = nil
}

type packInflater struct {
	input  *bufio.Reader
	reader io.ReadCloser
	buffer [32 << 10]byte
}

var packInflaters = sync.Pool{New: func() any {
	return &packInflater{input: bufio.NewReaderSize(nil, 8192), reader: nil, buffer: [32 << 10]byte{}}
}}

// readPacked reconstructs a packed object. It walks the delta chain down to a
// cached or undeltified base reading only record headers, then inflates and
// applies one delta at a time back up. Chain depth costs one position per
// link, never stack frames or retained delta instructions.
func (s *objectStorage) readPacked(p *objectPack, offset int64, id gitobj.Hash) (*storedObject, error) {
	type link struct {
		id     gitobj.Hash
		pack   *objectPack
		offset int64
	}
	var chain []link
	var base *storedObject
	for base == nil {
		if err := s.ctx.Err(); err != nil {
			return nil, err
		}
		if base = s.cached(id); base != nil {
			break
		}
		if o, ok := s.disk.get(id); ok {
			s.objects.Put(o)
			base = o
			break
		}
		e, err := s.inflate(p, offset, false)
		if err != nil {
			return nil, fmt.Errorf("pack object %s: %w", id, err)
		}
		if !e.kind.IsDelta() {
			base = &storedObject{id: id, kind: e.kind, raw: e.raw}
			s.keep(base)
			break
		}
		if len(chain) == maxDeltaChain {
			return nil, fmt.Errorf("git delta chain for %s exceeds %d links", chain[0].id, maxDeltaChain)
		}
		chain = append(chain, link{id, p, offset})
		if e.kind == gitobj.OFSDeltaObject {
			offset = e.baseOffset
			if id, err = p.index.FindHash(offset); err != nil {
				return nil, err
			}
			continue
		}
		id = e.baseID
		next, nextOffset, err := s.locate(id)
		if err != nil {
			return nil, err
		}
		if next == nil {
			if base, err = s.readFallback(id); err != nil {
				return nil, err
			}
			break
		}
		p, offset = next, nextOffset
	}
	for i := len(chain) - 1; i >= 0; i-- {
		l := chain[i]
		e, err := s.inflate(l.pack, l.offset, true)
		if err != nil {
			return nil, fmt.Errorf("pack object %s: %w", l.id, err)
		}
		raw, err := applyDelta(s.ctx, base.raw, e.raw, s.limit)
		if err != nil {
			return nil, fmt.Errorf("delta %s: %w", l.id, err)
		}
		base = &storedObject{id: l.id, kind: base.kind, raw: raw}
		s.keep(base)
	}
	return base, nil
}

// packEntry is one inflated pack record. Deltas name their base by offset
// (OFS) or by object ID (REF).
type packEntry struct {
	kind       gitobj.ObjectType
	baseOffset int64
	baseID     gitobj.Hash
	raw        string
}

// inflate reads the record at offset. A delta's instructions are inflated only
// when deltas is set; otherwise its header is enough to find the base.
func (s *objectStorage) inflate(p *objectPack, offset int64, deltas bool) (packEntry, error) {
	var e packEntry
	if offset < 12 || offset >= p.end {
		return e, errors.New("git pack offset out of bounds")
	}
	inflater := packInflaters.Get().(*packInflater)
	defer func() { inflater.input.Reset(nil); packInflaters.Put(inflater) }()
	r := inflater.input
	r.Reset(io.NewSectionReader(p.file, offset, p.end-offset))
	header, err := gitpack.ReadHeader(r, offset, p.hashSize, s.limit)
	if errors.Is(err, gitpack.ErrLimit) {
		return e, limitf("%s", err)
	}
	if err != nil {
		return e, err
	}
	e.kind, e.baseOffset, e.baseID = header.Type, header.BaseOffset, header.BaseID
	size := header.Size
	if e.kind.IsDelta() && !deltas {
		return e, nil
	}
	if inflater.reader == nil {
		inflater.reader, err = zlib.NewReader(r)
	} else {
		err = inflater.reader.(zlib.Resetter).Reset(r, nil)
	}
	if err != nil {
		return e, err
	}
	var out strings.Builder
	out.Grow(int(size))
	_, err = io.CopyBuffer(&out, io.LimitReader(contextReader{s.ctx, inflater.reader}, size+1), inflater.buffer[:])
	if closeErr := inflater.reader.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return e, err
	}
	if int64(out.Len()) != size {
		return e, errors.New("git packed object size mismatch")
	}
	e.raw = out.String()
	return e, nil
}

// applyDelta preserves the scan's skipped-content classification for shared decoder limits.
func applyDelta(ctx context.Context, base, delta string, limit int64) (string, error) {
	raw, err := gitpack.ApplyDelta(ctx, base, delta, limit)
	if errors.Is(err, gitpack.ErrLimit) {
		return "", limitf("%s", err)
	}
	return raw, err
}
