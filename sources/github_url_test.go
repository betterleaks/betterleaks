package sources

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_parseGitHubURL(t *testing.T) {
	cases := []struct {
		name     string
		url      string
		want     *parsedGitHubURL
		wantErr  bool
	}{
		{
			name: "issue",
			url:  "https://github.com/owner/repo/issues/123",
			want: &parsedGitHubURL{Owner: "owner", Repo: "repo", Resource: "issue", ID: "123", Host: "github.com"},
		},
		{
			name: "pr",
			url:  "https://github.com/owner/repo/pull/42",
			want: &parsedGitHubURL{Owner: "owner", Repo: "repo", Resource: "pr", ID: "42", Host: "github.com"},
		},
		{
			name: "discussion",
			url:  "https://github.com/owner/repo/discussions/7",
			want: &parsedGitHubURL{Owner: "owner", Repo: "repo", Resource: "discussion", ID: "7", Host: "github.com"},
		},
		{
			name: "release",
			url:  "https://github.com/owner/repo/releases/tag/v1.0.0",
			want: &parsedGitHubURL{Owner: "owner", Repo: "repo", Resource: "release", ID: "v1.0.0", Host: "github.com"},
		},
		{
			name: "actions run",
			url:  "https://github.com/owner/repo/actions/runs/9876543210",
			want: &parsedGitHubURL{Owner: "owner", Repo: "repo", Resource: "actions_run", ID: "9876543210", Host: "github.com"},
		},
		{
			name: "gist",
			url:  "https://gist.github.com/user/abc123def456",
			want: &parsedGitHubURL{Owner: "user", Repo: "", Resource: "gist", ID: "abc123def456", Host: "gist.github.com"},
		},
		{
			name: "trailing slash",
			url:  "https://github.com/owner/repo/issues/1/",
			want: &parsedGitHubURL{Owner: "owner", Repo: "repo", Resource: "issue", ID: "1", Host: "github.com"},
		},
		{
			name: "GHE issue",
			url:  "https://github.example.com/owner/repo/issues/55",
			want: &parsedGitHubURL{Owner: "owner", Repo: "repo", Resource: "issue", ID: "55", Host: "github.example.com"},
		},
		{
			name: "GHE gist",
			url:  "https://gist.github.example.com/user/deadbeef",
			want: &parsedGitHubURL{Owner: "user", Repo: "", Resource: "gist", ID: "deadbeef", Host: "gist.github.example.com"},
		},
		// Error cases
		{
			name:    "no scheme",
			url:     "github.com/owner/repo/issues/1",
			wantErr: true,
		},
		{
			name:    "too short",
			url:     "https://github.com/owner/repo",
			wantErr: true,
		},
		{
			name:    "unsupported type",
			url:     "https://github.com/owner/repo/commits/abc",
			wantErr: true,
		},
		{
			name:    "release without tag",
			url:     "https://github.com/owner/repo/releases/latest",
			wantErr: true,
		},
		{
			name:    "actions without runs",
			url:     "https://github.com/owner/repo/actions/workflows/ci.yml",
			wantErr: true,
		},
		{
			name:    "gist missing id",
			url:     "https://gist.github.com/user",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseGitHubURL(tc.url)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
