package gitpack

import (
	"context"
	"encoding/binary"
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
