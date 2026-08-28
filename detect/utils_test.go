package detect

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

func TestSamePath(t *testing.T) {
	// A native-separator config path and the forward-slash fragment path the
	// file source produces must compare equal. The bug only bit on Windows,
	// where filepath.FromSlash yields backslashes.
	cfg := filepath.FromSlash("proj/sub/.betterleaks.toml")
	assert.True(t, samePath("proj/sub/.betterleaks.toml", cfg))
	assert.False(t, samePath("proj/sub/other.toml", cfg))
}

func TestFilterTracksComponentOwnership(t *testing.T) {
	component := &report.ComponentFinding{
		RuleID: "generic-username",
		Location: report.Location{
			StartLine: 170},
		Secret:          "invalid",
		RuleSpecificity: 100,
	}

	t.Run("preserves a primary matching its own component", func(t *testing.T) {
		primary := report.Finding{
			RuleID: "generic-password",
			Location: report.Location{
				StartLine: 170},
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
			RuleID: "generic-password",
			Location: report.Location{
				StartLine: 170},
			Match:           "password: 'hunter2'",
			Secret:          "hunter2",
			RuleSpecificity: 20,
			ComponentSets: []report.ComponentSet{
				{Components: []*report.ComponentFinding{component}},
			},
		}
		standaloneComponent := report.Finding{
			RuleID: "generic-username",
			Location: report.Location{
				StartLine: 170},
			Match:  "login: 'invalid'",
			Secret: "invalid",
		}

		assert.Equal(t, []report.Finding{primary}, filter([]report.Finding{primary, standaloneComponent}))
	})

	t.Run("preserves the same value at a different location", func(t *testing.T) {
		primary := report.Finding{
			RuleID: "generic-password",
			Location: report.Location{
				StartLine: 170},
			Secret: "hunter2",
			ComponentSets: []report.ComponentSet{
				{Components: []*report.ComponentFinding{{
					RuleID: "generic-username",
					Location: report.Location{
						StartLine:   170,
						EndLine:     170,
						StartColumn: 10,
						EndColumn:   16,
					},
					Secret: "invalid",
				}}},
			},
		}
		ownedStandalone := report.Finding{
			RuleID: "generic-username",
			Location: report.Location{
				StartLine:   170,
				EndLine:     170,
				StartColumn: 10,
				EndColumn:   16,
			},
			Secret: "invalid",
		}
		unownedStandalone := report.Finding{
			RuleID: "generic-username",
			Location: report.Location{
				StartLine:   170,
				EndLine:     170,
				StartColumn: 30,
				EndColumn:   36,
			},
			Secret: "invalid",
		}

		assert.Equal(t,
			[]report.Finding{primary, unownedStandalone},
			filter([]report.Finding{primary, ownedStandalone, unownedStandalone}),
		)
	})

	t.Run("allows another owner's component to take precedence", func(t *testing.T) {
		ownedComponent := &report.ComponentFinding{
			RuleID: "specific-rule",
			Location: report.Location{
				StartLine: 170},
			Match:           "credential: 'prefix-invalid-suffix'",
			Secret:          "prefix-invalid-suffix",
			RuleSpecificity: 100,
		}
		primary := report.Finding{
			RuleID: "composite-rule",
			Location: report.Location{
				StartLine: 169},
			Match:           "composite: 'hunter2'",
			Secret:          "hunter2",
			RuleSpecificity: 50,
			ComponentSets: []report.ComponentSet{
				{Components: []*report.ComponentFinding{ownedComponent}},
			},
		}
		standalone := report.Finding{
			RuleID: "generic-rule",
			Location: report.Location{
				StartLine: 170},
			Match:           "credential: 'invalid'",
			Secret:          "invalid",
			RuleSpecificity: 20,
		}

		assert.Equal(t, []report.Finding{primary}, filter([]report.Finding{primary, standalone}))
	})

	t.Run("suppresses a composite surfaced inside another primary", func(t *testing.T) {
		nestedComponent := &report.ComponentFinding{
			RuleID: "nested-composite",
			Location: report.Location{
				StartLine: 170},
			Secret: "shared",
		}
		outerPrimary := report.Finding{
			RuleID: "outer-primary",
			Location: report.Location{
				StartLine: 169},
			Secret: "outer",
			ComponentSets: []report.ComponentSet{
				{Components: []*report.ComponentFinding{nestedComponent}},
			},
		}
		nestedPrimary := report.Finding{
			RuleID: "nested-composite",
			Location: report.Location{
				StartLine: 170},
			Secret: "shared",
			ComponentSets: []report.ComponentSet{
				{Components: []*report.ComponentFinding{{RuleID: "leaf",
					Location: report.Location{
						StartLine: 171},
					Secret: "leaf"}}},
			},
		}

		assert.Equal(t, []report.Finding{outerPrimary}, filter([]report.Finding{outerPrimary, nestedPrimary}))
	})
}

func scmLinkFinding(commit, path string, startLine, endLine int) report.Finding {
	return report.Finding{
		Attributes: map[string]string{
			sources.AttrGitSHA: commit,
			sources.AttrPath:   path,
		},
		Location: report.Location{
			StartLine: startLine, EndLine: endLine},
	}
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
			finding:   scmLinkFinding("20553ad96a4a080c94a54d677db97eed8ce2560d", "metrics/% of sales/.env", 25, 25),
			want:      "https://github.com/gitleaks/test/blob/20553ad96a4a080c94a54d677db97eed8ce2560d/metrics/%25%20of%20sales/.env#L25",
		},
		"github - multi line": {
			platform:  "github",
			remoteURL: "https://github.com/gitleaks/test",
			finding:   scmLinkFinding("7bad9f7654cf9701b62400281748c0e8efd97666", "config.json", 235, 238),
			want:      "https://github.com/gitleaks/test/blob/7bad9f7654cf9701b62400281748c0e8efd97666/config.json#L235-L238",
		},
		"github - markdown": {
			platform:  "github",
			remoteURL: "https://github.com/gitleaks/test",
			finding:   scmLinkFinding("1fc8961d172f39ffb671766e472aa76f8d713e87", "docs/guides/ecosystem/discordjs.MD", 34, 34),
			want:      "https://github.com/gitleaks/test/blob/1fc8961d172f39ffb671766e472aa76f8d713e87/docs/guides/ecosystem/discordjs.MD?plain=1#L34",
		},
		"github - jupyter notebook": {
			platform:  "github",
			remoteURL: "https://github.com/gitleaks/test",
			finding:   scmLinkFinding("8f56bd2369595bcadbb007e88ba294630fb05c7b", "Cloud/IPYNB/Overlapping Recommendation algorithm _OCuLaR_.ipynb", 293, 293),
			want:      "https://github.com/gitleaks/test/blob/8f56bd2369595bcadbb007e88ba294630fb05c7b/Cloud/IPYNB/Overlapping%20Recommendation%20algorithm%20_OCuLaR_.ipynb?plain=1#L293",
		},

		// GitLab
		"gitlab - single line": {
			platform:  "gitlab",
			remoteURL: "https://gitlab.com/example-org/example-group/gitleaks",
			finding:   scmLinkFinding("213ffd1c9bfa906eb4c7731771132c58a4ca0139", ".gitlab-ci.yml", 41, 41),
			want:      "https://gitlab.com/example-org/example-group/gitleaks/blob/213ffd1c9bfa906eb4c7731771132c58a4ca0139/.gitlab-ci.yml#L41",
		},
		"gitlab - multi line": {
			platform:  "gitlab",
			remoteURL: "https://gitlab.com/example-org/example-group/gitleaks",
			finding:   scmLinkFinding("63410f74e23a4e51e1f60b9feb073b5d325af878", ".vscode/launchSettings.json", 6, 8),
			want:      "https://gitlab.com/example-org/example-group/gitleaks/blob/63410f74e23a4e51e1f60b9feb073b5d325af878/.vscode/launchSettings.json#L6-8",
		},

		// Azure DevOps
		"azuredevops - single line": {
			platform:  "azuredevops",
			remoteURL: "https://dev.azure.com/exampleorganisation/exampleproject/_git/exampleRepository",
			finding:   scmLinkFinding("20553ad96a4a080c94a54d677db97eed8ce2560d", "examplefile.json", 25, 25),
			want:      "https://dev.azure.com/exampleorganisation/exampleproject/_git/exampleRepository/commit/20553ad96a4a080c94a54d677db97eed8ce2560d?path=/examplefile.json&line=25&lineStartColumn=1&lineEndColumn=10000000&type=2&lineStyle=plain&_a=files",
		},

		// Azure DevOps
		"azuredevops - multi line": {
			platform:  "azuredevops",
			remoteURL: "https://dev.azure.com/exampleorganisation/exampleproject/_git/exampleRepository",
			finding:   scmLinkFinding("20553ad96a4a080c94a54d677db97eed8ce2560d", "examplefile.json", 25, 30),
			want:      "https://dev.azure.com/exampleorganisation/exampleproject/_git/exampleRepository/commit/20553ad96a4a080c94a54d677db97eed8ce2560d?path=/examplefile.json&line=25&lineEnd=30&lineStartColumn=1&lineEndColumn=10000000&type=2&lineStyle=plain&_a=files",
		},

		// Gitea
		"gitea - single line": {
			platform:  "gitea",
			remoteURL: "https://gitea.com/exampleorganisation/exampleproject",
			finding:   scmLinkFinding("20553ad96a4a080c94a54d677db97eed8ce2560d", "examplefile.json", 25, 25),
			want:      "https://gitea.com/exampleorganisation/exampleproject/src/commit/20553ad96a4a080c94a54d677db97eed8ce2560d/examplefile.json#L25",
		},
		"gitea- multi line": {
			platform:  "gitea",
			remoteURL: "https://gitea.com/exampleorganisation/exampleproject",
			finding:   scmLinkFinding("20553ad96a4a080c94a54d677db97eed8ce2560d", "examplefile.json", 25, 30),
			want:      "https://gitea.com/exampleorganisation/exampleproject/src/commit/20553ad96a4a080c94a54d677db97eed8ce2560d/examplefile.json#L25-L30",
		},
		"gitea - markdown": {
			platform:  "gitea",
			remoteURL: "https://gitea.com/exampleorganisation/exampleproject",
			finding:   scmLinkFinding("20553ad96a4a080c94a54d677db97eed8ce2560d", "Readme.md", 34, 34),
			want:      "https://gitea.com/exampleorganisation/exampleproject/src/commit/20553ad96a4a080c94a54d677db97eed8ce2560d/Readme.md?display=source#L34",
		},
		// bitbucket
		"bitbucket - single line": {
			platform:  "bitbucket",
			remoteURL: "https://bitbucket.org/exampleorganisation/exampleproject",
			finding:   scmLinkFinding("20553ad96a4a080c94a54d677db97eed8ce2560d", "examplefile.json", 25, 25),
			want:      "https://bitbucket.org/exampleorganisation/exampleproject/src/20553ad96a4a080c94a54d677db97eed8ce2560d/examplefile.json#lines-25",
		},
		"bitbucket- multi line": {
			platform:  "bitbucket",
			remoteURL: "https://bitbucket.org/exampleorganisation/exampleproject",
			finding:   scmLinkFinding("20553ad96a4a080c94a54d677db97eed8ce2560d", "examplefile.json", 25, 30),
			want:      "https://bitbucket.org/exampleorganisation/exampleproject/src/20553ad96a4a080c94a54d677db97eed8ce2560d/examplefile.json#lines-25:30",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			actual := createScmLink(tt.platform, tt.remoteURL, tt.finding)
			assert.Equal(t, tt.want, actual)
		})
	}
}
