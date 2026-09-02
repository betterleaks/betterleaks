package cmd

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/logging"
)

func TestInitLogConfiguresOnlyCommandRuntime(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	var globalOutput bytes.Buffer
	globalLogger := logging.NewConsole(&globalOutput, logging.ConsoleOptions{
		Level:   slog.LevelDebug,
		NoColor: true,
	})
	slog.SetDefault(globalLogger)

	var commandOutput bytes.Buffer
	runtime := &commandRuntime{stderr: &commandOutput}
	err := initLog(
		&GlobalFlags{LogLevel: "debug", RegexEngine: "re2"},
		&kong.Context{},
		runtime,
	)
	require.NoError(t, err)

	runtime.Logger().Debug("command message")
	slog.Debug("global message")

	assert.Contains(t, commandOutput.String(), "command message")
	assert.NotContains(t, commandOutput.String(), "global message")
	assert.Contains(t, globalOutput.String(), "global message")
	assert.NotContains(t, globalOutput.String(), "command message")
	assert.Same(t, globalLogger, slog.Default())
}
