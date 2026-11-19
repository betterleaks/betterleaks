// Package gitpack contains bounded Git pack decoding shared by fetching and scanning.
package gitpack

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrLimit reports that reconstructing an object would exceed the caller's budget.
var ErrLimit = errors.New("git pack limit exceeded")

type deltaProgram struct {
	code           string
	source, target int
}

func parseDelta(source int, delta string, limit int64) (deltaProgram, error) {
	readSize := func() (uint64, error) {
		var n uint64
		for shift := uint(0); shift < 63 && len(delta) > 0; shift += 7 {
			b := delta[0]
			delta = delta[1:]
			n |= uint64(b&127) << shift
			if b&128 == 0 {
				return n, nil
			}
		}
		return 0, errors.New("invalid Git delta size")
	}
	sourceSize, err := readSize()
	if err != nil {
		return deltaProgram{}, err
	}
	if sourceSize != uint64(source) {
		return deltaProgram{}, errors.New("git delta base size mismatch")
	}
	targetSize, err := readSize()
	if err != nil {
		return deltaProgram{}, err
	}
	if limit < 0 || targetSize > uint64(limit) || targetSize > uint64(int(^uint(0)>>1)) {
		return deltaProgram{}, fmt.Errorf("%w: delta size %d exceeds reconstruction limit %d", ErrLimit, targetSize, limit)
	}
	return deltaProgram{code: delta, source: source, target: int(targetSize)}, nil
}

// walk verifies every instruction. A nil visitor validates the declared output
// size before allocating it. Nonempty literals come directly from the program.
func (p deltaProgram) walk(ctx context.Context, emit func(offset, size int, literal string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	remaining := uint64(p.target)
	code := p.code
	for ops := 0; len(code) > 0; ops++ {
		if ops&1023 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		cmd := code[0]
		code = code[1:]
		var offset, size uint64
		var literal string
		if cmd&128 != 0 {
			for j := uint(0); j < 7; j++ {
				if cmd&(1<<j) == 0 {
					continue
				}
				if len(code) == 0 {
					return errors.New("truncated Git delta copy")
				}
				v := uint64(code[0])
				code = code[1:]
				if j < 4 {
					offset |= v << (j * 8)
				} else {
					size |= v << ((j - 4) * 8)
				}
			}
			if size == 0 {
				size = 65536
			}
			if size > remaining || offset > uint64(p.source) || size > uint64(p.source)-offset {
				return errors.New("git delta copy out of bounds")
			}
		} else {
			size = uint64(cmd)
			if size == 0 || size > uint64(len(code)) || size > remaining {
				return errors.New("invalid Git delta literal")
			}
			literal, code = code[:size], code[size:]
		}
		if emit != nil {
			if err := emit(int(offset), int(size), literal); err != nil {
				return err
			}
		}
		remaining -= size
	}
	if remaining != 0 {
		return errors.New("git delta result size mismatch")
	}
	return nil
}

func writeDeltaBytes(ctx context.Context, out *strings.Builder, data string) error {
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := min(len(data), 32<<10)
		out.WriteString(data[:n])
		data = data[n:]
	}
	return nil
}

// ApplyDelta validates the complete instruction stream before allocating its
// declared result, then copies directly from the immutable base and literals.
func ApplyDelta(ctx context.Context, base, delta string, limit int64) (string, error) {
	p, err := parseDelta(len(base), delta, limit)
	if err != nil {
		return "", err
	}
	return p.apply(ctx, base)
}

func (p deltaProgram) apply(ctx context.Context, base string) (string, error) {
	if err := p.walk(ctx, nil); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var out strings.Builder
	out.Grow(p.target)
	err := p.walk(ctx, func(offset, size int, literal string) error {
		if literal != "" {
			out.WriteString(literal)
			return nil
		}
		return writeDeltaBytes(ctx, &out, base[offset:offset+size])
	})
	if err != nil {
		return "", err
	}
	return out.String(), nil
}
