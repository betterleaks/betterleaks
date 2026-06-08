package detect

import (
	"slices"
	"testing"

	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

// TestFilter covers the two suppression branches of filter(): dropping a
// standalone finding that is already surfaced as a required component, and
// dropping a generic-rule finding when a more specific rule matched the same
// secret on the same line and commit.
func TestFilter(t *testing.T) {
	sha := sources.AttrGitSHA
	tests := map[string]struct {
		in   []report.Finding
		want []string // expected RuleIDs, in order
	}{
		"no findings": {in: nil, want: nil},
		"standalone duplicate of a required component is dropped": {
			in: []report.Finding{
				{RuleID: "composite", StartLine: 1, Secret: "composite",
					RequiredSets: []report.RequiredSet{{Components: []*report.RequiredFinding{{StartLine: 5, Secret: "x"}}}}},
				{RuleID: "standalone", StartLine: 5, Secret: "x"},
			},
			want: []string{"composite"},
		},
		"generic suppressed by specific rule on same line+sha": {
			in: []report.Finding{
				{RuleID: "generic-api-key", StartLine: 3, Secret: "abc", Attributes: map[string]string{sha: "s1"}},
				{RuleID: "aws-key", StartLine: 3, Secret: "xabcx", Attributes: map[string]string{sha: "s1"}},
			},
			want: []string{"aws-key"},
		},
		"generic kept when the commit differs": {
			in: []report.Finding{
				{RuleID: "generic-api-key", StartLine: 3, Secret: "abc", Attributes: map[string]string{sha: "s1"}},
				{RuleID: "aws-key", StartLine: 3, Secret: "xabcx", Attributes: map[string]string{sha: "s2"}},
			},
			want: []string{"generic-api-key", "aws-key"},
		},
		"generic kept when the specific secret does not contain it": {
			in: []report.Finding{
				{RuleID: "generic-api-key", StartLine: 3, Secret: "abc", Attributes: map[string]string{sha: "s1"}},
				{RuleID: "aws-key", StartLine: 3, Secret: "xyz", Attributes: map[string]string{sha: "s1"}},
			},
			want: []string{"generic-api-key", "aws-key"},
		},
		"generic not suppressed by another generic": {
			in: []report.Finding{
				{RuleID: "generic-api-key", StartLine: 3, Secret: "abc", Attributes: map[string]string{sha: "s1"}},
				{RuleID: "generic-other", StartLine: 3, Secret: "xabcx", Attributes: map[string]string{sha: "s1"}},
			},
			want: []string{"generic-api-key", "generic-other"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := filter(tc.in)
			var ids []string
			for _, f := range got {
				ids = append(ids, f.RuleID)
			}
			if !slices.Equal(ids, tc.want) {
				t.Fatalf("filter() RuleIDs = %v, want %v", ids, tc.want)
			}
		})
	}
}

func TestFilterByStatus(t *testing.T) {
	mk := func(id, status string) report.Finding {
		return report.Finding{RuleID: id, ValidationStatus: status}
	}
	all := []report.Finding{mk("a", "valid"), mk("b", "invalid"), mk("c", "")}

	tests := map[string]struct {
		filter map[string]struct{}
		want   []string
	}{
		"empty filter returns all": {filter: nil, want: []string{"a", "b", "c"}},
		"single status":            {filter: map[string]struct{}{"valid": {}}, want: []string{"a"}},
		"none pseudo-status":       {filter: map[string]struct{}{"none": {}}, want: []string{"c"}},
		"status plus none":         {filter: map[string]struct{}{"valid": {}, "none": {}}, want: []string{"a", "c"}},
		"no match":                 {filter: map[string]struct{}{"revoked": {}}, want: nil},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			d := &Detector{ValidationStatusFilter: tc.filter}
			got := d.FilterByStatus(all)
			var ids []string
			for _, f := range got {
				ids = append(ids, f.RuleID)
			}
			if !slices.Equal(ids, tc.want) {
				t.Fatalf("FilterByStatus() RuleIDs = %v, want %v", ids, tc.want)
			}
		})
	}
}
