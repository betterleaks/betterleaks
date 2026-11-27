package gitpack

import (
	"context"
	"errors"
	"sort"
)

// DeltaChain reconstructs successive versions of a single object. Small deltas
// against large objects can carry forward borrowed byte ranges until a caller
// needs contiguous bytes for scanning or caching.
type DeltaChain struct {
	raw             string
	pieces, scratch []deltaPiece
	size            int
}
type deltaPiece struct {
	end  int // exclusive offset in this version
	text string
}

// Reset starts a chain at an immutable, materialized base.
func (s *DeltaChain) Reset(base string) {
	clear(s.pieces)
	s.pieces = s.pieces[:0]
	s.raw, s.size = base, len(base)
}

// Text returns the materialized version when available. Passing true to
// Apply guarantees that this method returns the complete new contents.
func (s *DeltaChain) Text() (string, bool) { return s.raw, len(s.pieces) == 0 }

// Apply verifies one complete delta. When materialize is false, subsequent
// deltas may read unchanged ranges from earlier versions without copying them.
func (s *DeltaChain) Apply(ctx context.Context, delta string, limit int64, materialize bool) error {
	p, err := parseDelta(s.size, delta, limit)
	if err != nil {
		return err
	}
	if !materialize && s.size >= 256<<10 && len(delta) <= 64<<10 {
		err := s.applyPieces(ctx, p)
		switch {
		case err == nil:
			s.raw = ""
			return nil
		case !errors.Is(err, errFragmented):
			return err
		}
	}
	// Write contiguous results directly from the source pieces. This avoids
	// copying an intermediate version and leaves the chain intact on error.
	raw, err := p.apply(ctx, s.raw, s.pieces)
	if err == nil {
		s.Reset(raw)
	}
	return err
}

var errFragmented = errors.New("too many Git delta spans")

// applyPieces leaves the previous version intact when a fragmented delta
// exceeds the metadata budget. Apply can then copy from the original pieces.
func (s *DeltaChain) applyPieces(ctx context.Context, p deltaProgram) error {
	source := s.pieces
	if len(source) == 0 {
		source = []deltaPiece{{end: s.size, text: s.raw}}
	}
	out := s.scratch[:0]
	size := 0
	appendPiece := func(text string) error {
		if len(out) >= 2048 {
			return errFragmented
		}
		size += len(text)
		out = append(out, deltaPiece{size, text})
		return nil
	}
	err := p.walk(ctx, func(offset, n int, literal string) error {
		if literal != "" {
			return appendPiece(literal)
		}
		return visitRange(source, offset, n, appendPiece)
	})
	if err != nil {
		clear(out)
		s.scratch = out[:0]
		return err
	}
	clear(s.pieces)
	s.pieces, s.scratch = out, s.pieces[:0]
	s.size = size
	return nil
}

func visitRange(pieces []deltaPiece, offset, n int, visit func(string) error) error {
	i := sort.Search(len(pieces), func(i int) bool { return pieces[i].end > offset })
	for n > 0 {
		piece := pieces[i]
		start := offset - (piece.end - len(piece.text))
		count := min(n, len(piece.text)-start)
		if err := visit(piece.text[start : start+count]); err != nil {
			return err
		}
		offset += count
		n -= count
		i++
	}
	return nil
}
