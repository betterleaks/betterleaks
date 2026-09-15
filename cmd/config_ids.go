package cmd

import (
	"fmt"
	"slices"
	"strings"
)

type ConfigShowIDsCmd struct {
	Validation bool   `help:"Show only rule IDs that support validation."`
	Analysis   bool   `help:"Show only rule IDs that support analysis."`
	Revocation bool   `help:"Show only rule IDs that support revocation."`
	Path       string `arg:"" optional:"" name:"config-path" help:"Config file whose rule IDs should be listed."`
}

func (cmd *ConfigShowIDsCmd) Run(cli *CLI, runtime *commandRuntime) error {
	resolved, err := resolveConfig(runtime, cli.Config, cmd.Path)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(resolved.cfg.Rules))
	for _, rule := range resolved.cfg.Rules {
		if cmd.Validation && strings.TrimSpace(rule.ValidateExpr) == "" {
			continue
		}
		if cmd.Analysis && strings.TrimSpace(rule.AnalyzeExpr) == "" {
			continue
		}
		if cmd.Revocation && strings.TrimSpace(rule.RevokeExpr) == "" {
			continue
		}
		ids = append(ids, rule.ID)
	}
	slices.Sort(ids)
	for _, id := range ids {
		if _, err := fmt.Fprintln(runtime.stdout, id); err != nil {
			return err
		}
	}
	return nil
}
