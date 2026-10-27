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

// ApplyDelta validates the complete instruction stream before allocating its
// declared result, then copies directly from the immutable base and literals.
// It never retains a chain of full-sized intermediate scratch buffers.
func ApplyDelta(ctx context.Context, base, delta string, limit int64) (string, error) {
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
		return "", err
	}
	if sourceSize != uint64(len(base)) {
		return "", errors.New("git delta base size mismatch")
	}
	targetSize, err := readSize()
	if err != nil {
		return "", err
	}
	if limit < 0 || targetSize > uint64(limit) || targetSize > uint64(int(^uint(0)>>1)) {
		return "", fmt.Errorf("%w: delta size %d exceeds reconstruction limit %d", ErrLimit, targetSize, limit)
	}
	var out strings.Builder
	for pass := 0; pass < 2; pass++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if pass == 1 {
			out.Grow(int(targetSize))
		}
		remaining := targetSize
		for at, ops := 0, 0; at < len(delta); ops++ {
			if ops&1023 == 0 {
				if err := ctx.Err(); err != nil {
					return "", err
				}
			}
			cmd := delta[at]
			at++
			if cmd&128 != 0 {
				var offset, size uint64
				for j := uint(0); j < 7; j++ {
					if cmd&(1<<j) == 0 {
						continue
					}
					if at == len(delta) {
						return "", errors.New("truncated Git delta copy")
					}
					v := uint64(delta[at])
					at++
					if j < 4 {
						offset |= v << (j * 8)
					} else {
						size |= v << ((j - 4) * 8)
					}
				}
				if size == 0 {
					size = 65536
				}
				if size > remaining || offset > sourceSize || size > sourceSize-offset {
					return "", errors.New("git delta copy out of bounds")
				}
				if pass == 1 {
					for end := offset + size; offset < end; {
						if err := ctx.Err(); err != nil {
							return "", err
						}
						next := min(offset+32<<10, end)
						out.WriteString(base[offset:next])
						offset = next
					}
				}
				remaining -= size
			} else {
				n := int(cmd)
				if n == 0 || n > len(delta)-at || uint64(n) > remaining {
					return "", errors.New("invalid Git delta literal")
				}
				if pass == 1 {
					out.WriteString(delta[at : at+n])
				}
				at += n
				remaining -= uint64(n)
			}
		}
		if remaining != 0 {
			return "", errors.New("git delta result size mismatch")
		}
	}
	return out.String(), nil
}
