package gitpack

import (
	"context"
	"encoding/binary"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type cancelCopyContext struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *cancelCopyContext) Err() error {
	c.checks--
	if c.checks == 0 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestApplyDeltaCancellationDuringCopy(t *testing.T) {
	base := strings.Repeat("x", 4<<20)
	delta := binary.AppendUvarint(nil, uint64(len(base)))
	delta = binary.AppendUvarint(delta, uint64(len(base)))
	delta = append(delta, 0xc0, 64) // One instruction copies 64 << 16 bytes.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// Four checks precede copying; cancel after the first 32 KiB chunk.
	counted := &cancelCopyContext{Context: ctx, cancel: cancel, checks: 6}
	got, err := ApplyDelta(counted, base, string(delta), int64(len(base)))
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, got)
}

func TestDeltaChainAcrossBorrowedRanges(t *testing.T) {
	// Rotate binary data and insert fresh literals. Later copies cross the
	// boundaries of older edits and can move backwards in their source.
	random := rand.New(rand.NewPCG(21, 73))
	want := strings.Repeat("π\x00\xff\t\r\n", 48<<10)
	var chain DeltaChain
	chain.Reset(want)
	for i := range 64 {
		pivot := 1 + random.IntN(len(want)-1)
		literal := []byte{byte(i), 0xff, 0}
		program := binary.AppendUvarint(nil, uint64(len(want)))
		program = binary.AppendUvarint(program, uint64(len(want)+len(literal)))
		program = appendTestCopy(program, pivot, len(want)-pivot)
		program = append(program, byte(len(literal)))
		program = append(program, literal...)
		program = appendTestCopy(program, 0, pivot)
		want = want[pivot:] + string(literal) + want[:pivot]
		checkpoint := i%8 == 7
		require.NoError(t, chain.Apply(t.Context(), string(program), 1<<20, checkpoint))
		got, ready := chain.Text()
		require.Equal(t, checkpoint, ready)
		if ready {
			require.Equal(t, want, got)
		}
	}
}

func TestFragmentedDeltaFallsBackAndValidatesTail(t *testing.T) {
	base := strings.Repeat("b", 256<<10)
	const inserts = 3000
	program := binary.AppendUvarint(nil, uint64(len(base)))
	program = binary.AppendUvarint(program, uint64(len(base)+inserts))
	program = append(program, strings.Repeat("\x01a", inserts)...)
	program = appendTestCopy(program, 0, len(base))
	var chain DeltaChain
	chain.Reset(base)
	require.NoError(t, chain.Apply(t.Context(), string(program), 1<<20, false))
	got, ready := chain.Text()
	require.True(t, ready)
	require.Equal(t, strings.Repeat("a", inserts)+base, got)
	chain.Reset(base)
	require.Error(t, chain.Apply(t.Context(), string(append(program, 0)), 1<<20, false))
	chain.Reset(base)
	require.ErrorIs(t, chain.Apply(t.Context(), string(program), int64(len(base)), false), ErrLimit)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, chain.Apply(ctx, string(program), 1<<20, false), context.Canceled)
}

func TestLargeDeltaReadsBorrowedRanges(t *testing.T) {
	base := strings.Repeat("abcdef012345", 32<<10)
	pivot := len(base)/2 + 1
	first := binary.AppendUvarint(nil, uint64(len(base)))
	first = binary.AppendUvarint(first, uint64(len(base)+3))
	first = appendTestCopy(first, pivot, len(base)-pivot)
	first = append(first, 3, 'x', 'y', 'z')
	first = appendTestCopy(first, 0, pivot)
	rotated := base[pivot:] + "xyz" + base[:pivot]

	var chain DeltaChain
	chain.Reset(base)
	require.NoError(t, chain.Apply(t.Context(), string(first), 1<<20, false))
	_, ready := chain.Text()
	require.False(t, ready)

	// Cancel a checkpoint in the middle of copying borrowed bytes. The next
	// delta still names the previous version as its base.
	checkpoint := binary.AppendUvarint(nil, uint64(len(rotated)))
	checkpoint = binary.AppendUvarint(checkpoint, uint64(len(rotated)+1))
	checkpoint = appendTestCopy(checkpoint, 0, len(rotated))
	checkpoint = append(checkpoint, 1, '!')
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	counted := &cancelCopyContext{Context: ctx, cancel: cancel, checks: 8}
	require.ErrorIs(t, chain.Apply(counted, string(checkpoint), 1<<20, true), context.Canceled)

	// Force contiguous output with a large literal stream. Both copies
	// cross the inserted text, and the second starts before the first.
	literal := strings.Repeat("L", 127)
	const repeats = 520
	want := rotated[100:] + strings.Repeat(literal, repeats) + rotated[:pivot+10]
	next := binary.AppendUvarint(nil, uint64(len(rotated)))
	next = binary.AppendUvarint(next, uint64(len(want)))
	next = appendTestCopy(next, 100, len(rotated)-100)
	for range repeats {
		next = append(next, byte(len(literal)))
		next = append(next, literal...)
	}
	next = appendTestCopy(next, 0, pivot+10)
	require.Error(t, chain.Apply(t.Context(), string(next)+"\x00", 1<<20, true))
	require.NoError(t, chain.Apply(t.Context(), string(next), 1<<20, true))
	got, ready := chain.Text()
	require.True(t, ready)
	require.Equal(t, want, got)
}

// A Git copy opcode can carry four little-endian offset bytes and three length bytes.
func appendTestCopy(dst []byte, offset, size int) []byte {
	dst = append(dst, 0xff)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(offset))
	return append(dst, byte(size), byte(size>>8), byte(size>>16))
}
