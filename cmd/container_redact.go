package cmd

import (
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/betterleaks/betterleaks/report"
)

// containerFindingForDisplay masks a finding's known secrets without mutating
// the original, which the final report needs for scan-wide redaction.
func containerFindingForDisplay(f report.Finding, percent uint) report.Finding {
	if percent == 0 {
		return f
	}
	f.Attributes = maps.Clone(f.Attributes)
	f.CaptureGroups = maps.Clone(f.CaptureGroups)
	f.ComponentSets = slices.Clone(f.ComponentSets)
	for i := range f.ComponentSets {
		set := &f.ComponentSets[i]
		set.Components = slices.Clone(set.Components)
		for j, component := range set.Components {
			copy := *component
			copy.CaptureGroups = maps.Clone(component.CaptureGroups)
			set.Components[j] = &copy
		}
	}
	findings := []report.Finding{f}
	redactContainerFindings(findings, percent)
	return findings[0]
}

// Image labels are repeated in the provenance of other findings. Redact known
// secrets across the scan before writing the final report, including surrounding
// context that can contain another credential from the same metadata document.
func redactContainerFindings(findings []report.Finding, percent uint) {
	if percent == 0 {
		return
	}
	secrets := map[string]struct{}{}
	for _, f := range findings {
		if f.Secret != "" {
			secrets[f.Secret] = struct{}{}
		}
		for _, set := range f.ComponentSets {
			for _, comp := range set.Components {
				if comp.Secret != "" {
					secrets[comp.Secret] = struct{}{}
				}
			}
		}
	}
	ordered := make([]string, 0, len(secrets))
	for secret := range secrets {
		ordered = append(ordered, secret)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if len(ordered[i]) == len(ordered[j]) {
			return ordered[i] < ordered[j]
		}
		return len(ordered[i]) > len(ordered[j])
	})
	pairs := make([]string, 0, 2*len(ordered))
	for _, secret := range ordered {
		masked := report.MaskSecret(secret, percent)
		if percent >= 100 {
			masked = "REDACTED"
		}
		pairs = append(pairs, secret, masked)
	}
	replace := strings.NewReplacer(pairs...)
	redactAttrs := func(attrs map[string]string) {
		for key, value := range attrs {
			attrs[key] = replace.Replace(value)
		}
	}
	for i := range findings {
		f := &findings[i]
		redactAttrs(f.Attributes)
		redactAttrs(f.CaptureGroups)
		f.SyncDeprecatedSourceFields()
		f.Line = replace.Replace(f.Line)
		f.Match = replace.Replace(f.Match)
		f.MatchContext = replace.Replace(f.MatchContext)
		// Secret itself remains available to v1's normal percentage redaction.
		for _, set := range f.ComponentSets {
			for _, comp := range set.Components {
				redactAttrs(comp.CaptureGroups)
				comp.Line = replace.Replace(comp.Line)
				comp.Match = replace.Replace(comp.Match)
			}
		}
	}
}
