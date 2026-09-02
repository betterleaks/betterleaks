package sources

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSourceLoggingIsOptIn(t *testing.T) {
	assert.Equal(t, slog.DiscardHandler, loggerOrDiscard(nil).Handler())

	var output bytes.Buffer
	source := &Files{
		Logger: slog.New(slog.NewJSONHandler(&output, nil)),
		Path:   filepath.Join(t.TempDir(), "missing"),
	}

	err := source.Fragments(t.Context(), func(Fragment, error) error { return nil })
	require.NoError(t, err)
	assert.Contains(t, output.String(), "skipping")
	assert.Contains(t, output.String(), source.Path)
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

	assert.Contains(t, firstOutput.String(), first.Path)
	assert.NotContains(t, firstOutput.String(), second.Path)
	assert.Contains(t, secondOutput.String(), second.Path)
	assert.NotContains(t, secondOutput.String(), first.Path)
}
