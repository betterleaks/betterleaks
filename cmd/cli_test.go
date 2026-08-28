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
