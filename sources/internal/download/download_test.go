package download

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type trackedReader struct {
	io.Reader
	closed bool
}

func (r *trackedReader) Close() error { r.closed = true; return nil }

func TestWithFileReaderOwnershipAndCleanup(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	stop := errors.New("stop scan")
	for _, tc := range []struct {
		name      string
		limit     int64
		cancelled bool
		scanErr   error
		wantErr   error
		wantScan  bool
	}{
		{name: "success", wantScan: true},
		{name: "callback error", scanErr: stop, wantErr: stop, wantScan: true},
		{name: "oversized", limit: 3},
		{name: "exact limit", limit: 7, wantScan: true},
		{name: "cancelled", cancelled: true, wantErr: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			reader := &trackedReader{Reader: strings.NewReader("content")}
			called := false
			err := WithFile(ctx, Options{Reader: reader, MaxSize: tc.limit}, func(file *os.File) error {
				called = true
				body, err := io.ReadAll(file)
				require.NoError(t, err)
				require.Equal(t, "content", string(body))
				return tc.scanErr
			})
			require.ErrorIs(t, err, tc.wantErr)
			require.Equal(t, tc.wantScan, called)
			require.True(t, reader.closed)
			files, err := os.ReadDir(tmp)
			require.NoError(t, err)
			require.Empty(t, files)
		})
	}
}
