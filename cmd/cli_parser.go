package cmd

import (
	"reflect"
	"slices"

	"github.com/alecthomas/kong"
)

// cliParser routes leading flags to the explicitly selected command. Kong's
// default:"withargs" otherwise binds these flags to auto, even when a different
// command is selected later. The real parse still enforces command-local scope.
type cliParser struct {
	*kong.Kong
}

func (p *cliParser) Parse(args []string) (*kong.Context, error) {
	return p.Kong.Parse(p.commandFirstArgs(p.Model.Node, expandRuleFlagShorthands(args)))
}

func (p *cliParser) commandFirstArgs(node *kong.Node, args []string) []string {
	if len(args) == 0 || len(node.Children) == 0 {
		return args
	}

	// Trace only the flag prefix, using copies so routing cannot mark real flags
	// as set or active. No hooks, defaults, validators, or command runs execute.
	// Kong's own decoders handle short flags, attached values and custom types.
	probeNode := *node
	probeNode.Parent = nil
	probeNode.Children = nil
	probeNode.DefaultCmd = nil
	probeNode.Positional = nil
	probeNode.Flags = nil
	seen := map[string]bool{}
	addFlags := func(flags []*kong.Flag) {
		for _, flag := range flags {
			if seen[flag.Name] {
				continue
			}
			seen[flag.Name] = true
			copyFlag, copyValue := *flag, *flag.Value
			copyValue.Target = reflect.New(flag.Target.Type()).Elem()
			copyFlag.Value, copyValue.Flag = &copyValue, &copyFlag
			probeNode.Flags = append(probeNode.Flags, &copyFlag)
		}
	}
	for ancestor := node; ancestor != nil; ancestor = ancestor.Parent {
		addFlags(ancestor.Flags)
	}
	var addChildren func(*kong.Node)
	addChildren = func(parent *kong.Node) {
		for _, child := range parent.Children {
			addFlags(child.Flags)
			addChildren(child)
		}
	}
	addChildren(node)
	probeApp := *p.Model
	probeApp.Node = &probeNode
	probeParser := *p.Kong
	probeParser.Model = &probeApp
	trace, err := kong.Trace(&probeParser, args)
	if err != nil {
		return args
	}
	// With no children or positionals, tracing stops at the first non-flag (or
	// malformed flag). Leave errors to the real parser instead of guessing past
	// them. The last successfully consumed flag records the remaining tokens.
	index := 0
	for _, step := range trace.Path {
		if step.Flag != nil {
			index = len(args) - len(step.Remainder())
		}
	}
	if index >= len(args) {
		return args
	}
	if args[index] == "--" && node.DefaultCmd != nil && node.DefaultCmd.Tag.Default == "withargs" {
		// Make the default explicit so command-like paths after -- stay literal.
		return append([]string{node.DefaultCmd.Name}, args...)
	}
	for _, child := range node.Children {
		if child.Type != kong.CommandNode || !commandMatches(child, args[index]) {
			continue
		}
		rest := make([]string, 0, len(args)-1)
		rest = append(rest, args[:index]...)
		rest = append(rest, args[index+1:]...)
		return append([]string{args[index]}, p.commandFirstArgs(child, rest)...)
	}
	return args
}

func commandMatches(node *kong.Node, arg string) bool {
	if node.Name == arg {
		return true
	}
	return slices.Contains(node.Aliases, arg)
}
