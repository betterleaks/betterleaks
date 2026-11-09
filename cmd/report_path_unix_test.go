//go:build unix

package cmd

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckReportPathWritableKeepsNamedPipeReader(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "report.fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	report := make(chan string, 1)
	go func() {
		data, _ := os.ReadFile(fifo)
		report <- string(data)
	}()

	require.NoError(t, checkReportPathWritable(fifo))

	var writer *os.File
	require.Eventually(t, func() bool {
		f, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		writer = f
		return err == nil
	}, 5*time.Second, 10*time.Millisecond)
	_, err := writer.WriteString("report")
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	assert.Equal(t, "report", <-report)
}
