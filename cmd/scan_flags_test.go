package cmd

import (
	"testing"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/require"
)

func TestScanFlagsAreCommandLocal(t *testing.T) {
	scanOnly := []string{
		"exit-code",
		"silent",
		"output",
		"confidence",
		"max-target-megabytes",
		"jobs",
		"ignore-file",
		"ignore-allow-comments",
		"redact",
		"no-banner",
		"disable-rule",
		"isolate-rule",
		"match-context",
		"max-decode-depth",
		"max-archive-depth",
		"validation",
		"analysis",
		"validation-status",
		"provider-workers",
		"provider-debug",
		"diagnostics",
		"diagnostics-dir",
	}

	_, parser := newCLIParserForTest(t)
	scanNodes := []*kong.Node{
		commandNode(t, parser.Model.Node, "dir"),
		commandNode(t, parser.Model.Node, "git"),
		commandNode(t, parser.Model.Node, "github"),
		commandNode(t, parser.Model.Node, "gitlab"),
		commandNode(t, parser.Model.Node, "huggingface"),
		commandNode(t, parser.Model.Node, "s3"),
		commandNode(t, parser.Model.Node, "stdin"),
	}
	validateNode := commandNode(t, parser.Model.Node, "validate")
	configNode := commandNode(t, parser.Model.Node, "config")
	for _, name := range scanOnly {
		require.False(t, nodeHasFlag(parser.Model.Node, name), name)
		require.False(t, nodeHasFlag(configNode, name), name)
		require.False(t, nodeHasFlag(validateNode, name), name)
		for _, node := range scanNodes {
			require.True(t, nodeHasFlag(node, name), "%s: %s", node.Name, name)
		}
	}

	sharedWithValidate := []string{
		"jsonl",
		"provider-timeout",
		"provider-max-requests",
		"provider-rps",
		"provider-rps-rule",
		"validation-extract-empty",
		"provider-env-vars",
	}
	for _, name := range sharedWithValidate {
		require.False(t, nodeHasFlag(parser.Model.Node, name), name)
		require.False(t, nodeHasFlag(configNode, name), name)
		require.True(t, nodeHasFlag(validateNode, name), name)
		for _, node := range scanNodes {
			require.True(t, nodeHasFlag(node, name), "%s: %s", node.Name, name)
		}
	}

	for _, deprecated := range []string{
		"validation-workers", "validation-debug", "validation-timeout",
		"validation-max-requests", "validation-rps", "validation-rps-rule",
		"validation-env-vars",
	} {
		require.False(t, nodeHasFlag(validateNode, deprecated), deprecated)
		for _, node := range scanNodes {
			require.False(t, nodeHasFlag(node, deprecated), "%s: %s", node.Name, deprecated)
		}
	}
}

func TestRedactFlagSupportsImplicitAndExplicitPercentages(t *testing.T) {
	cli, err := parseCLIForTest(t, "dir", "--redact")
	require.NoError(t, err)
	require.Equal(t, redactFlag(100), cli.Directory.Redact)

	cli, err = parseCLIForTest(t, "dir", "--redact=20")
	require.NoError(t, err)
	require.Equal(t, redactFlag(20), cli.Directory.Redact)
}

func nodeHasFlag(node *kong.Node, name string) bool {
	for _, flag := range node.Flags {
		if flag.Name == name {
			return true
		}
	}
	return false
}

func commandNode(t *testing.T, parent *kong.Node, name string) *kong.Node {
	t.Helper()
	for _, child := range parent.Children {
		if child.Name == name {
			return child
		}
	}
	t.Fatalf("command %q not found", name)
	return nil
}
