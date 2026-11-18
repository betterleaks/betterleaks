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

// A Git copy opcode can carry four little-endian offset bytes and three length bytes.
func appendTestCopy(dst []byte, offset, size int) []byte {
	dst = append(dst, 0xff)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(offset))
	return append(dst, byte(size), byte(size>>8), byte(size>>16))
}
