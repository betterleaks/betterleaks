package scan

import (
	"maps"

	"github.com/betterleaks/betterleaks/v2/internal/confidence"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
)

// exprAttributes returns the source attributes used by rule expressions, including
// the promoted path. The map is independent of the finding so local helpers may
// write to it. Report consumers should use Location.Path.
func exprAttributes(f report.Finding) map[string]string {
	attrs := make(map[string]string, len(f.Attributes)+1)
	maps.Copy(attrs, f.Attributes)
	delete(attrs, sources.AttrPath)
	delete(attrs, confidence.Attribute)
	if f.Location.Path != "" {
		attrs[sources.AttrPath] = f.Location.Path
	}
	if link := findingSCMLink(f); link != "" {
		attrs[sources.AttrURL] = link
	}
	return attrs
}

// exprFinding returns the fixed-shape map[string]string used as the `finding`
// variable in local filter expressions.
func exprFinding(f report.Finding) map[string]string {
	return map[string]string{
		"secret":      f.Match.Value,
		"match":       f.Match.Full,
		"line":        f.Match.Line,
		"rule_id":     f.RuleID,
		"description": f.Description,
		"confidence":  f.Confidence,
		"context":     f.Match.Context,
	}
}
