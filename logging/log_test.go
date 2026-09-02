package logging

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConsoleHandlerFormatsRecords(t *testing.T) {
	var output bytes.Buffer
	logger := NewConsole(&output, ConsoleOptions{Level: LevelTrace, NoColor: true})
	record := slog.NewRecord(
		time.Date(2026, time.September, 2, 12, 22, 0, 0, time.Local),
		slog.LevelError,
		"request failed",
		0,
	)
	record.AddAttrs(
		slog.String("z", "last"),
		slog.Any("error", errors.New("connection refused")),
		slog.String("path", "/tmp/example"),
		slog.Any("scopes", []string{"read", "write"}),
	)

	require.NoError(t, logger.Handler().Handle(t.Context(), record))
	assert.Equal(t,
		"12:22PM ERR request failed error=\"connection refused\" path=/tmp/example scopes=[\"read\",\"write\"] z=last\n",
		output.String(),
	)
}

func TestConsoleHandlerUsesShortLevelNames(t *testing.T) {
	var output bytes.Buffer
	logger := NewConsole(&output, ConsoleOptions{Level: LevelTrace, NoColor: true})
	timestamp := time.Date(2026, time.September, 2, 12, 22, 0, 0, time.Local)
	levels := []struct {
		level slog.Level
		name  string
	}{
		{LevelTrace, "TRC"},
		{slog.LevelDebug, "DBG"},
		{slog.LevelInfo, "INF"},
		{slog.LevelWarn, "WRN"},
		{slog.LevelError, "ERR"},
		{LevelFatal, "FTL"},
	}
	for _, level := range levels {
		record := slog.NewRecord(timestamp, level.level, "message", 0)
		require.NoError(t, logger.Handler().Handle(t.Context(), record))
	}

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	require.Len(t, lines, len(levels))
	for i, level := range levels {
		assert.Equal(t, "12:22PM "+level.name+" message", lines[i])
	}
}

func TestConsoleHandlerFiltersByLevel(t *testing.T) {
	var output bytes.Buffer
	logger := NewConsole(&output, ConsoleOptions{Level: slog.LevelWarn, NoColor: true})

	logger.Debug("hidden")
	logger.Warn("visible")

	assert.NotContains(t, output.String(), "hidden")
	assert.Contains(t, output.String(), "visible")
}

func TestConsoleHandlerPreservesAttrsAndGroups(t *testing.T) {
	var output bytes.Buffer
	logger := NewConsole(&output, ConsoleOptions{Level: slog.LevelInfo, NoColor: true}).
		With("component", "source").
		WithGroup("request").
		With("method", "GET")

	logger.Info("sending", "url", "https://example.com")

	assert.Contains(t, output.String(), "sending component=source request.method=GET request.url=https://example.com")
}

func TestConsoleHandlerColorsCanBeDisabled(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	var colored bytes.Buffer
	logger := NewConsole(&colored, ConsoleOptions{Level: slog.LevelInfo})
	record := slog.NewRecord(
		time.Date(2026, time.September, 2, 12, 22, 0, 0, time.Local),
		slog.LevelInfo,
		"complete",
		0,
	)
	require.NoError(t, logger.Handler().Handle(t.Context(), record))
	assert.Contains(t, colored.String(), "\x1b[90m12:22PM\x1b[0m")
	assert.Contains(t, colored.String(), "\x1b[32mINF\x1b[0m")
	assert.Contains(t, colored.String(), "\x1b[1mcomplete\x1b[0m")

	var plain bytes.Buffer
	logger = NewConsole(&plain, ConsoleOptions{Level: slog.LevelInfo, NoColor: true})
	require.NoError(t, logger.Handler().Handle(t.Context(), record))
	assert.Equal(t, "12:22PM INF complete\n", plain.String())
}

func TestConsoleHandlerWritesRecordsAtomically(t *testing.T) {
	var output bytes.Buffer
	logger := NewConsole(&output, ConsoleOptions{Level: slog.LevelInfo, NoColor: true})

	const records = 100
	var workers sync.WaitGroup
	workers.Add(records)
	for i := range records {
		go func() {
			defer workers.Done()
			logger.Info("record", "id", i)
		}()
	}
	workers.Wait()

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	require.Len(t, lines, records)
	for _, line := range lines {
		assert.Contains(t, line, " INF record id=")
	}
}

func TestTraceUsesDefaultLogger(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	var output bytes.Buffer
	slog.SetDefault(NewConsole(&output, ConsoleOptions{Level: LevelTrace, NoColor: true}))
	Trace("trace message", "source", "test")

	assert.Contains(t, output.String(), " TRC trace message")
	assert.Contains(t, output.String(), "source=test")
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestConsoleHandlerReturnsWriteErrors(t *testing.T) {
	logger := NewConsole(failingWriter{}, ConsoleOptions{Level: slog.LevelInfo, NoColor: true})
	record := slog.NewRecord(time.Now(), slog.LevelInfo, "message", 0)

	err := logger.Handler().Handle(context.Background(), record)
	require.EqualError(t, err, "write failed")
}
