package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/require"
)

func newCLIParserForTest(t *testing.T) (*CLI, *kong.Kong) {
	t.Helper()
	cli := &CLI{}
	runtime := &commandRuntime{
		Context: context.Background(),
		stdin:   strings.NewReader(""),
		stdout:  new(bytes.Buffer),
		stderr:  new(bytes.Buffer),
		exit:    func(int) {},
	}
	parser, err := newCLIParser(cli, runtime)
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
