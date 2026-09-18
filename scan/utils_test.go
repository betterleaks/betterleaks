package scan

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"log/slog"
	"testing"

	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/stretchr/testify/assert"
)

func filterForTest(findings []report.Finding) []report.Finding {
	scanner := Scanner{logger: slog.New(slog.DiscardHandler), ruleIndexByID: make(map[string]int)}
	for id, specificity := range map[string]int{
		"generic-username": 100, "specific-rule": 100,
		"generic-password": 20, "generic-rule": 20, "composite-rule": 50,
		"outer-primary": 0, "nested-composite": 0, "leaf": 0,
	} {
		scanner.ruleIndexByID[id] = len(scanner.rulesBySpecificity)
		scanner.rulesBySpecificity = append(scanner.rulesBySpecificity, compiledRule{rule: config.Rule{ID: id, Specificity: specificity}})
	}
	return scanner.filter(findings)
}

func TestFilterTracksComponentOwnership(t *testing.T) {
	component := report.ComponentFinding{
		RuleID: "generic-username",
		Location: report.Location{
			StartLine: 170},
		Match: report.Match{Value: "invalid"},
	}

	t.Run("preserves a primary matching its own component", func(t *testing.T) {
		primary := report.Finding{
			RuleID: "generic-password",
			Location: report.Location{
				StartLine: 170},
			Match: report.Match{Full: "password: 'invalid'", Value: "invalid"},
			ComponentSets: []report.ComponentSet{
				{Components: []report.ComponentFinding{component}},
			},
		}

		assert.Equal(t, []report.Finding{primary}, filterForTest([]report.Finding{primary}))
	})

	t.Run("suppresses a standalone finding owned by another primary", func(t *testing.T) {
		primary := report.Finding{
			RuleID: "generic-password",
			Location: report.Location{
				StartLine: 170},
			Match: report.Match{Full: "password: 'hunter2'", Value: "hunter2"},
			ComponentSets: []report.ComponentSet{
				{Components: []report.ComponentFinding{component}},
			},
		}
		standaloneComponent := report.Finding{
			RuleID: "generic-username",
			Location: report.Location{
				StartLine: 170},
			Match: report.Match{Full: "login: 'invalid'", Value: "invalid"},
		}

		assert.Equal(t, []report.Finding{primary}, filterForTest([]report.Finding{primary, standaloneComponent}))
	})

	t.Run("preserves the same value at a different location", func(t *testing.T) {
		primary := report.Finding{
			RuleID: "generic-password",
			Location: report.Location{
				StartLine: 170},
			Match: report.Match{Value: "hunter2"},
			ComponentSets: []report.ComponentSet{
				{Components: []report.ComponentFinding{{
					RuleID: "generic-username",
					Location: report.Location{
						StartLine:   170,
						EndLine:     170,
						StartColumn: 10,
						EndColumn:   16,
					},
					Match: report.Match{Value: "invalid"},
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
			Match: report.Match{Value: "invalid"},
		}
		unownedStandalone := report.Finding{
			RuleID: "generic-username",
			Location: report.Location{
				StartLine:   170,
				EndLine:     170,
				StartColumn: 30,
				EndColumn:   36,
			},
			Match: report.Match{Value: "invalid"},
		}

		assert.Equal(t,
			[]report.Finding{primary, unownedStandalone},
			filterForTest([]report.Finding{primary, ownedStandalone, unownedStandalone}),
		)
	})

	t.Run("allows another owner's component to take precedence", func(t *testing.T) {
		ownedComponent := report.ComponentFinding{
			RuleID: "specific-rule",
			Location: report.Location{
				StartLine: 170},
			Match: report.Match{Full: "credential: 'prefix-invalid-suffix'", Value: "prefix-invalid-suffix"},
		}
		primary := report.Finding{
			RuleID: "composite-rule",
			Location: report.Location{
				StartLine: 169},
			Match: report.Match{Full: "composite: 'hunter2'", Value: "hunter2"},
			ComponentSets: []report.ComponentSet{
				{Components: []report.ComponentFinding{ownedComponent}},
			},
		}
		standalone := report.Finding{
			RuleID: "generic-rule",
			Location: report.Location{
				StartLine: 170},
			Match: report.Match{Full: "credential: 'invalid'", Value: "invalid"},
		}

		assert.Equal(t, []report.Finding{primary}, filterForTest([]report.Finding{primary, standalone}))
	})

	t.Run("suppresses a composite surfaced inside another primary", func(t *testing.T) {
		nestedComponent := report.ComponentFinding{
			RuleID: "nested-composite",
			Location: report.Location{
				StartLine: 170},
			Match: report.Match{Value: "shared"},
		}
		outerPrimary := report.Finding{
			RuleID: "outer-primary",
			Location: report.Location{
				StartLine: 169},
			Match: report.Match{Value: "outer"},
			ComponentSets: []report.ComponentSet{
				{Components: []report.ComponentFinding{nestedComponent}},
			},
		}
		nestedPrimary := report.Finding{
			RuleID: "nested-composite",
			Location: report.Location{
				StartLine: 170},
			Match: report.Match{Value: "shared"},
			ComponentSets: []report.ComponentSet{
				{Components: []report.ComponentFinding{{RuleID: "leaf",
					Location: report.Location{
						StartLine: 171},
					Match: report.Match{Value: "leaf"}}}},
			},
		}

		assert.Equal(t, []report.Finding{outerPrimary}, filterForTest([]report.Finding{outerPrimary, nestedPrimary}))
	})
}

func scmLinkFinding(commit, path string, startLine, endLine int) report.Finding {
	return report.Finding{
		Attributes: map[string]string{
			sources.AttrGitSHA: commit,
		},
		Location: report.Location{
			Path: path, StartLine: startLine, EndLine: endLine},
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

func TestCommitMessageSCMLinks(t *testing.T) {
	finding := scmLinkFinding("abc123", "", 3, 5)
	finding.SetAttr(sources.AttrResource, sources.ResourceGitCommitMessage)
	for platform, suffix := range map[string]string{
		"github": "/commit/abc123", "gitlab": "/-/commit/abc123",
		"azuredevops": "/commit/abc123", "gitea": "/commit/abc123",
		"bitbucket": "/commits/abc123",
	} {
		assert.Equal(t, "https://example.com/repo"+suffix, createScmLink(platform, "https://example.com/repo", finding), platform)
	}
	assert.Empty(t, createScmLink("none", "https://example.com/repo", finding))
}

func TestTagMessageSCMLinks(t *testing.T) {
	finding := scmLinkFinding("abc123", "", 3, 5)
	finding.SetAttr(sources.AttrResource, sources.ResourceGitTagMessage)
	finding.SetAttr(sources.AttrGitTagName, "original-name")
	finding.SetAttr(sources.AttrGitTagRef, "refs/tags/release/v1#100%")
	for platform, suffix := range map[string]string{
		"github": "/releases/tag/release%2Fv1%23100%25",
		"gitlab": "/-/tags/release%2Fv1%23100%25",
		"gitea":  "/releases/tag/release%2Fv1%23100%25",
	} {
		assert.Equal(t, "https://example.com/repo"+suffix, createScmLink(platform, "https://example.com/repo", finding), platform)
	}
	for _, platform := range []string{"none", "unknown", "bitbucket", "azuredevops"} {
		assert.Empty(t, createScmLink(platform, "https://example.com/repo", finding))
	}
	delete(finding.Attributes, sources.AttrGitTagRef)
	assert.Empty(t, createScmLink("github", "https://example.com/repo", finding), "nested tags without a ref have no tag page")
}
