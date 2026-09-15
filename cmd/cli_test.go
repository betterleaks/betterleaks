package cmd

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/betterleaks/betterleaks/v2/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newCLIParserForTest(t *testing.T) (*CLI, *kong.Kong) {
	t.Helper()
	cli := &CLI{}
	root, _ := newTestCLI(t)
	parser, err := newCLIParser(cli, root.runtime)
	require.NoError(t, err)
	return cli, parser
}

func parseCLIForTest(t *testing.T, args ...string) (*CLI, error) {
	t.Helper()
	cli, parser := newCLIParserForTest(t)
	_, err := parser.Parse(expandRuleFlagShorthands(args))
	return cli, err
}

func TestFilesystemShorthand(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "current directory", args: []string{"."}},
		{name: "relative directory", args: []string{"testdata"}},
		{name: "absolute path", args: []string{t.TempDir()}},
		{name: "file", args: []string{"config.toml"}},
		{name: "multiple paths", args: []string{"src", "config.toml"}},
		{name: "command name as path", args: []string{"./git"}},
		{name: "flags after path", args: []string{".", "--offline", "--follow-symlinks", "-j", "2"}},
		{name: "flags before path", args: []string{"--offline", "-j", "2", "."}},
		{name: "global flag value matches command", args: []string{"--config", "git", "."}},
		{name: "scan flag value matches command", args: []string{"--output", "git", "."}},
		{name: "literal flag as path", args: []string{"--", "--offline"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cli, parser := newCLIParserForTest(t)
			parsed, err := parser.Parse(test.args)
			require.NoError(t, err)
			require.Equal(t, "filesystem <path>", parsed.Command())

			explicit, err := parseCLIForTest(t, append([]string{"filesystem"}, test.args...)...)
			require.NoError(t, err)
			require.Equal(t, explicit.Directory, cli.Directory)
			require.Equal(t, explicit.GlobalFlags, cli.GlobalFlags)
		})
	}
}

func TestFilesystemShorthandPreservesCommands(t *testing.T) {
	for _, test := range []struct {
		args    []string
		command string
	}{
		{args: []string{"filesystem", "."}, command: "filesystem <path>"},
		{args: []string{"fs", "."}, command: "filesystem <path>"},
		{args: []string{"dir", "."}, command: "filesystem <path>"},
		{args: []string{"file", "config.toml"}, command: "filesystem <path>"},
		{args: []string{"files", "config.toml"}, command: "filesystem <path>"},
		{args: []string{"directory", "."}, command: "filesystem <path>"},
		{args: []string{"git", "."}, command: "git <repo>"},
		{args: []string{"stdin"}, command: "stdin"},
		{args: []string{"validate"}, command: "validate"},
		{args: []string{"analyze"}, command: "analyze"},
		{args: []string{"revoke"}, command: "revoke"},
		{args: []string{"version"}, command: "version"},
		{args: []string{"--config", "config.toml", "git", "."}, command: "git <repo>"},
	} {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			_, parser := newCLIParserForTest(t)
			parsed, err := parser.Parse(test.args)
			require.NoError(t, err)
			require.Equal(t, test.command, parsed.Command())
		})
	}
}

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

type testCLI struct {
	args    []string
	runtime *commandRuntime
}

func (c *testCLI) SetArgs(args []string) { c.args = args }
func (c *testCLI) SetIn(stdin io.Reader) { c.runtime.stdin = stdin }
func (c *testCLI) Execute() error        { return runCLI(c.args, c.runtime) }

func newTestCLI(t *testing.T) (*testCLI, *bytes.Buffer) {
	t.Helper()

	// A character device represents absent piped input without using process stdin.
	stdin, err := os.Open(os.DevNull)
	require.NoError(t, err)
	t.Cleanup(func() { _ = stdin.Close() })
	stdout := new(bytes.Buffer)
	runtime := &commandRuntime{
		Context: t.Context(),
		stdin:   stdin,
		stdout:  stdout,
		stderr:  io.Discard,
		exit:    func(int) {},
	}
	return &testCLI{runtime: runtime}, stdout
}

func TestDeprecatedScanCommandsRemoved(t *testing.T) {
	for _, command := range []string{"detect", "protect"} {
		// Removed command names are now ordinary paths for the filesystem shorthand.
		cli, parser := newCLIParserForTest(t)
		parsed, err := parser.Parse([]string{command})
		require.NoError(t, err)
		require.Equal(t, "filesystem <path>", parsed.Command())
		require.Equal(t, []string{command}, cli.Directory.Paths)
	}
}

type testErrorWriter struct{ err error }

func (w testErrorWriter) Write([]byte) (int, error) { return 0, w.err }
