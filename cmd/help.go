package cmd

import "github.com/alecthomas/kong"

func printCLIHelp(options kong.HelpOptions, ctx *kong.Context) error {
	if ctx.Selected() != nil || ctx.Model.DefaultCmd == nil {
		return kong.DefaultHelpPrinter(options, ctx)
	}

	if !options.Summary && isTerminalWriter(ctx.Stdout) && !helpFlagEnabled(ctx, "no-banner") && !helpFlagEnabled(ctx, "silent") {
		printBanner(ctx.Stdout, helpFlagEnabled(ctx, "no-color"))
	}

	// Show the default scan's flags in top-level help without making them global
	// parser flags. Copy the help view so command-local flag scopes stay intact.
	node := *ctx.Model.Node
	node.Flags = append(append([]*kong.Flag(nil), node.Flags...), node.DefaultCmd.Flags...)
	node.Detail = "Scan a target directly with betterleaks <path-or-url>, or choose a command below."
	app := *ctx.Model
	app.Node = &node
	parser := *ctx.Kong
	parser.Model = &app
	helpCtx := *ctx
	helpCtx.Kong = &parser
	return kong.DefaultHelpPrinter(options, &helpCtx)
}

// Kong prints help before it applies the parsed flags to the CLI struct.
func helpFlagEnabled(ctx *kong.Context, name string) bool {
	for _, step := range ctx.Path {
		if step.Flag != nil && step.Flag.Name == name {
			return ctx.FlagValue(step.Flag) == true
		}
	}
	return false
}
