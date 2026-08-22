package detect

import (
	"math"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/betterleaks/betterleaks/report"
)

func TestSamePath(t *testing.T) {
	// A native-separator config path and the forward-slash fragment path the
	// file source produces must compare equal. The bug only bit on Windows,
	// where filepath.FromSlash yields backslashes.
	cfg := filepath.FromSlash("proj/sub/.betterleaks.toml")
	assert.True(t, samePath("proj/sub/.betterleaks.toml", cfg))
	assert.False(t, samePath("proj/sub/other.toml", cfg))
}

func TestShannonEntropyMatchesByteReference(t *testing.T) {
	reference := func(value string) float64 {
		counts := make(map[byte]int)
		for i := range len(value) {
			counts[value[i]]++
		}
		var entropy float64
		for _, count := range counts {
			probability := float64(count) / float64(len(value))
			entropy -= probability * math.Log2(probability)
		}
		return entropy
	}
	for _, value := range []string{"a", "abcabc", "secret-token_123", "こんにちはsecret"} {
		assert.InDelta(t, reference(value), shannonEntropy(value), 1e-12)
	}
	assert.Zero(t, shannonEntropy(""))
}

func TestFilterTracksComponentOwnership(t *testing.T) {
	component := &report.ComponentFinding{
		RuleID:          "generic-username",
		StartLine:       170,
		Secret:          "invalid",
		RuleSpecificity: 100,
	}

	t.Run("preserves a primary matching its own component", func(t *testing.T) {
		primary := report.Finding{
			RuleID:          "generic-password",
			StartLine:       170,
			Match:           "password: 'invalid'",
			Secret:          "invalid",
			RuleSpecificity: 20,
			ComponentSets: []report.ComponentSet{
				{Components: []*report.ComponentFinding{component}},
			},
		}

		assert.Equal(t, []report.Finding{primary}, filter([]report.Finding{primary}))
	})

	t.Run("suppresses a standalone finding owned by another primary", func(t *testing.T) {
		primary := report.Finding{
			RuleID:          "generic-password",
			StartLine:       170,
			Match:           "password: 'hunter2'",
			Secret:          "hunter2",
			RuleSpecificity: 20,
			ComponentSets: []report.ComponentSet{
				{Components: []*report.ComponentFinding{component}},
			},
		}
		standaloneComponent := report.Finding{
			RuleID:    "generic-username",
			StartLine: 170,
			Match:     "login: 'invalid'",
			Secret:    "invalid",
		}

		assert.Equal(t, []report.Finding{primary}, filter([]report.Finding{primary, standaloneComponent}))
	})

	t.Run("preserves the same value at a different location", func(t *testing.T) {
		primary := report.Finding{
			RuleID:    "generic-password",
			StartLine: 170,
			Secret:    "hunter2",
			ComponentSets: []report.ComponentSet{
				{Components: []*report.ComponentFinding{{
					RuleID:      "generic-username",
					StartLine:   170,
					EndLine:     170,
					StartColumn: 10,
					EndColumn:   16,
					Secret:      "invalid",
				}}},
			},
		}
		ownedStandalone := report.Finding{
			RuleID:      "generic-username",
			StartLine:   170,
			EndLine:     170,
			StartColumn: 10,
			EndColumn:   16,
			Secret:      "invalid",
		}
		unownedStandalone := report.Finding{
			RuleID:      "generic-username",
			StartLine:   170,
			EndLine:     170,
			StartColumn: 30,
			EndColumn:   36,
			Secret:      "invalid",
		}

		assert.Equal(t,
			[]report.Finding{primary, unownedStandalone},
			filter([]report.Finding{primary, ownedStandalone, unownedStandalone}),
		)
	})

	t.Run("allows another owner's component to take precedence", func(t *testing.T) {
		ownedComponent := &report.ComponentFinding{
			RuleID:          "specific-rule",
			StartLine:       170,
			Match:           "credential: 'prefix-invalid-suffix'",
			Secret:          "prefix-invalid-suffix",
			RuleSpecificity: 100,
		}
		primary := report.Finding{
			RuleID:          "composite-rule",
			StartLine:       169,
			Match:           "composite: 'hunter2'",
			Secret:          "hunter2",
			RuleSpecificity: 50,
			ComponentSets: []report.ComponentSet{
				{Components: []*report.ComponentFinding{ownedComponent}},
			},
		}
		standalone := report.Finding{
			RuleID:          "generic-rule",
			StartLine:       170,
			Match:           "credential: 'invalid'",
			Secret:          "invalid",
			RuleSpecificity: 20,
		}

		assert.Equal(t, []report.Finding{primary}, filter([]report.Finding{primary, standalone}))
	})

	t.Run("suppresses a composite surfaced inside another primary", func(t *testing.T) {
		nestedComponent := &report.ComponentFinding{
			RuleID:    "nested-composite",
			StartLine: 170,
			Secret:    "shared",
		}
		outerPrimary := report.Finding{
			RuleID:    "outer-primary",
			StartLine: 169,
			Secret:    "outer",
			ComponentSets: []report.ComponentSet{
				{Components: []*report.ComponentFinding{nestedComponent}},
			},
		}
		nestedPrimary := report.Finding{
			RuleID:    "nested-composite",
			StartLine: 170,
			Secret:    "shared",
			ComponentSets: []report.ComponentSet{
				{Components: []*report.ComponentFinding{{RuleID: "leaf", StartLine: 171, Secret: "leaf"}}},
			},
		}

		assert.Equal(t, []report.Finding{outerPrimary}, filter([]report.Finding{outerPrimary, nestedPrimary}))
	})
}

func Test_createScmLink(t *testing.T) {
	tests := map[string]struct {
		platform  string
		remoteURL string
		finding   report.Finding
		want      string
	}{
		// None
		"no platform": {
			platform:  "none",
			remoteURL: "",
			want:      "",
		},

		// GitHub
		"github - single line": {
			platform:  "github",
			remoteURL: "https://github.com/gitleaks/test",
			finding: report.Finding{
				Commit:    "20553ad96a4a080c94a54d677db97eed8ce2560d",
				File:      "metrics/% of sales/.env",
				StartLine: 25,
				EndLine:   25,
			},
			want: "https://github.com/gitleaks/test/blob/20553ad96a4a080c94a54d677db97eed8ce2560d/metrics/%25%20of%20sales/.env#L25",
		},
		"github - multi line": {
			platform:  "github",
			remoteURL: "https://github.com/gitleaks/test",
			finding: report.Finding{
				Commit:    "7bad9f7654cf9701b62400281748c0e8efd97666",
				File:      "config.json",
				StartLine: 235,
				EndLine:   238,
			},
			want: "https://github.com/gitleaks/test/blob/7bad9f7654cf9701b62400281748c0e8efd97666/config.json#L235-L238",
		},
		"github - markdown": {
			platform:  "github",
			remoteURL: "https://github.com/gitleaks/test",
			finding: report.Finding{
				Commit:    "1fc8961d172f39ffb671766e472aa76f8d713e87",
				File:      "docs/guides/ecosystem/discordjs.MD",
				StartLine: 34,
				EndLine:   34,
			},
			want: "https://github.com/gitleaks/test/blob/1fc8961d172f39ffb671766e472aa76f8d713e87/docs/guides/ecosystem/discordjs.MD?plain=1#L34",
		},
		"github - jupyter notebook": {
			platform:  "github",
			remoteURL: "https://github.com/gitleaks/test",
			finding: report.Finding{
				Commit:    "8f56bd2369595bcadbb007e88ba294630fb05c7b",
				File:      "Cloud/IPYNB/Overlapping Recommendation algorithm _OCuLaR_.ipynb",
				StartLine: 293,
				EndLine:   293,
			},
			want: "https://github.com/gitleaks/test/blob/8f56bd2369595bcadbb007e88ba294630fb05c7b/Cloud/IPYNB/Overlapping%20Recommendation%20algorithm%20_OCuLaR_.ipynb?plain=1#L293",
		},

		// GitLab
		"gitlab - single line": {
			platform:  "gitlab",
			remoteURL: "https://gitlab.com/example-org/example-group/gitleaks",
			finding: report.Finding{
				Commit:    "213ffd1c9bfa906eb4c7731771132c58a4ca0139",
				File:      ".gitlab-ci.yml",
				StartLine: 41,
				EndLine:   41,
			},
			want: "https://gitlab.com/example-org/example-group/gitleaks/blob/213ffd1c9bfa906eb4c7731771132c58a4ca0139/.gitlab-ci.yml#L41",
		},
		"gitlab - multi line": {
			platform:  "gitlab",
			remoteURL: "https://gitlab.com/example-org/example-group/gitleaks",
			finding: report.Finding{
				Commit:    "63410f74e23a4e51e1f60b9feb073b5d325af878",
				File:      ".vscode/launchSettings.json",
				StartLine: 6,
				EndLine:   8,
			},
			want: "https://gitlab.com/example-org/example-group/gitleaks/blob/63410f74e23a4e51e1f60b9feb073b5d325af878/.vscode/launchSettings.json#L6-8",
		},

		// Azure DevOps
		"azuredevops - single line": {
			platform:  "azuredevops",
			remoteURL: "https://dev.azure.com/exampleorganisation/exampleproject/_git/exampleRepository",
			finding: report.Finding{
				Commit:    "20553ad96a4a080c94a54d677db97eed8ce2560d",
				File:      "examplefile.json",
				StartLine: 25,
				EndLine:   25,
			},
			want: "https://dev.azure.com/exampleorganisation/exampleproject/_git/exampleRepository/commit/20553ad96a4a080c94a54d677db97eed8ce2560d?path=/examplefile.json&line=25&lineStartColumn=1&lineEndColumn=10000000&type=2&lineStyle=plain&_a=files",
		},

		// Azure DevOps
		"azuredevops - multi line": {
			platform:  "azuredevops",
			remoteURL: "https://dev.azure.com/exampleorganisation/exampleproject/_git/exampleRepository",
			finding: report.Finding{
				Commit:    "20553ad96a4a080c94a54d677db97eed8ce2560d",
				File:      "examplefile.json",
				StartLine: 25,
				EndLine:   30,
			},
			want: "https://dev.azure.com/exampleorganisation/exampleproject/_git/exampleRepository/commit/20553ad96a4a080c94a54d677db97eed8ce2560d?path=/examplefile.json&line=25&lineEnd=30&lineStartColumn=1&lineEndColumn=10000000&type=2&lineStyle=plain&_a=files",
		},

		// Gitea
		"gitea - single line": {
			platform:  "gitea",
			remoteURL: "https://gitea.com/exampleorganisation/exampleproject",
			finding: report.Finding{
				Commit:    "20553ad96a4a080c94a54d677db97eed8ce2560d",
				File:      "examplefile.json",
				StartLine: 25,
				EndLine:   25,
			},
			want: "https://gitea.com/exampleorganisation/exampleproject/src/commit/20553ad96a4a080c94a54d677db97eed8ce2560d/examplefile.json#L25",
		},
		"gitea- multi line": {
			platform:  "gitea",
			remoteURL: "https://gitea.com/exampleorganisation/exampleproject",
			finding: report.Finding{
				Commit:    "20553ad96a4a080c94a54d677db97eed8ce2560d",
				File:      "examplefile.json",
				StartLine: 25,
				EndLine:   30,
			},
			want: "https://gitea.com/exampleorganisation/exampleproject/src/commit/20553ad96a4a080c94a54d677db97eed8ce2560d/examplefile.json#L25-L30",
		},
		"gitea - markdown": {
			platform:  "gitea",
			remoteURL: "https://gitea.com/exampleorganisation/exampleproject",
			finding: report.Finding{
				Commit:    "20553ad96a4a080c94a54d677db97eed8ce2560d",
				File:      "Readme.md",
				StartLine: 34,
				EndLine:   34,
			},
			want: "https://gitea.com/exampleorganisation/exampleproject/src/commit/20553ad96a4a080c94a54d677db97eed8ce2560d/Readme.md?display=source#L34",
		},
		// bitbucket
		"bitbucket - single line": {
			platform:  "bitbucket",
			remoteURL: "https://bitbucket.org/exampleorganisation/exampleproject",
			finding: report.Finding{
				Commit:    "20553ad96a4a080c94a54d677db97eed8ce2560d",
				File:      "examplefile.json",
				StartLine: 25,
				EndLine:   25,
			},
			want: "https://bitbucket.org/exampleorganisation/exampleproject/src/20553ad96a4a080c94a54d677db97eed8ce2560d/examplefile.json#lines-25",
		},
		"bitbucket- multi line": {
			platform:  "bitbucket",
			remoteURL: "https://bitbucket.org/exampleorganisation/exampleproject",
			finding: report.Finding{
				Commit:    "20553ad96a4a080c94a54d677db97eed8ce2560d",
				File:      "examplefile.json",
				StartLine: 25,
				EndLine:   30,
			},
			want: "https://bitbucket.org/exampleorganisation/exampleproject/src/20553ad96a4a080c94a54d677db97eed8ce2560d/examplefile.json#lines-25:30",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			actual := createScmLink(tt.platform, tt.remoteURL, tt.finding)
			assert.Equal(t, tt.want, actual)
		})
	}
}
