package detect

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/betterleaks/betterleaks/report"
)

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

// Test_locateMatch verifies the near-position fallback logic that
// disambiguates duplicate occurrences of the same match on a line.
func Test_locateMatch(t *testing.T) {
	tests := map[string]struct {
		rawLine  string
		rawMatch string
		startCol int
		want     int
	}{
		"empty line": {
			rawLine:  "",
			rawMatch: "abc",
			startCol: 1,
			want:     -1,
		},
		"empty match": {
			rawLine:  "abc",
			rawMatch: "",
			startCol: 1,
			want:     -1,
		},
		"exact position hit": {
			rawLine:  "prefix key=SECRET suffix",
			rawMatch: "key=SECRET",
			startCol: 8, // byte 7 is 'k', 1-indexed = 8
			want:     7,
		},
		"first of duplicates via startCol": {
			rawLine:  "tok tok",
			rawMatch: "tok",
			startCol: 1,
			want:     0,
		},
		"second of duplicates via startCol": {
			rawLine:  "tok tok",
			rawMatch: "tok",
			startCol: 5,
			want:     4,
		},
		"startCol slightly off - forward search finds nearer": {
			// startCol points 1 byte before the second "tok"
			rawLine:  "tok ...tok",
			rawMatch: "tok",
			startCol: 7, // byte 6, actual second "tok" is at byte 7
			want:     7, // forward search from byte 6 finds byte 7
		},
		"startCol past match - backward search finds it": {
			rawLine:  "abc SECRET def",
			rawMatch: "SECRET",
			startCol: 14, // past end of "SECRET"
			want:     4,  // backward search from byte 13 finds byte 4
		},
		"no startCol falls back to strings.Index": {
			rawLine:  "tok tok",
			rawMatch: "tok",
			startCol: 0,
			want:     0, // first occurrence
		},
		"match not in line": {
			rawLine:  "no match here",
			rawMatch: "SECRET",
			startCol: 1,
			want:     -1,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := locateMatch(tt.rawLine, tt.rawMatch, tt.startCol)
			assert.Equal(t, tt.want, got)
		})
	}
}
