package sources

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testLogRecord struct {
	Message string `json:"msg"`
	Path    string `json:"path"`
}

func TestSourceLoggingIsOptIn(t *testing.T) {
	assert.Equal(t, slog.DiscardHandler, loggerOrDiscard(nil).Handler())

	var output bytes.Buffer
	source := &Files{
		Logger: slog.New(slog.NewJSONHandler(&output, nil)),
		Path:   filepath.Join(t.TempDir(), "missing"),
	}

	err := source.Fragments(t.Context(), func(Fragment, error) error { return nil })
	require.NoError(t, err)
	record := decodeLogRecord(t, output.Bytes())
	assert.Equal(t, "skipping", record.Message)
	assert.Equal(t, source.Path, record.Path)
}

func TestSourceLoggersAreIndependent(t *testing.T) {
	var firstOutput, secondOutput bytes.Buffer
	first := &Files{
		Logger: slog.New(slog.NewJSONHandler(&firstOutput, nil)),
		Path:   filepath.Join(t.TempDir(), "first-missing"),
	}
	second := &Files{
		Logger: slog.New(slog.NewJSONHandler(&secondOutput, nil)),
		Path:   filepath.Join(t.TempDir(), "second-missing"),
	}

	yield := func(Fragment, error) error { return nil }
	require.NoError(t, first.Fragments(t.Context(), yield))
	require.NoError(t, second.Fragments(t.Context(), yield))

	firstRecord := decodeLogRecord(t, firstOutput.Bytes())
	secondRecord := decodeLogRecord(t, secondOutput.Bytes())
	assert.Equal(t, first.Path, firstRecord.Path)
	assert.NotEqual(t, second.Path, firstRecord.Path)
	assert.Equal(t, second.Path, secondRecord.Path)
	assert.NotEqual(t, first.Path, secondRecord.Path)
}

func decodeLogRecord(t *testing.T, data []byte) testLogRecord {
	t.Helper()
	var record testLogRecord
	require.NoError(t, json.Unmarshal(data, &record))
	return record
}
