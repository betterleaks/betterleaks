package scm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveRemoteURL(t *testing.T) {
	for _, tc := range []struct {
		remote   string
		platform Platform
		want     Platform
		url      string
	}{
		{"https://github.com/org/repo.git", UnknownPlatform, GitHubPlatform, "https://github.com/org/repo"},
		{"git@github.com:org/repo.git", UnknownPlatform, GitHubPlatform, "https://github.com/org/repo"},
		{"git@gitlab.com:group/sub/repo.git", UnknownPlatform, GitLabPlatform, "https://gitlab.com/group/sub/repo"},
		{"gitlab.com:group/repo.git", UnknownPlatform, GitLabPlatform, "https://gitlab.com/group/repo"},
		{"ssh://git@gitlab.com:2222/group/repo.git", UnknownPlatform, GitLabPlatform, "https://gitlab.com/group/repo"},
		{"git://github.com/org/repo.git", UnknownPlatform, GitHubPlatform, "https://github.com/org/repo"},
		{"https://user:password@github.com/org/repo.git?token=private#private", UnknownPlatform, GitHubPlatform, "https://github.com/org/repo"},
		{"https://git.example.test:8443/group/repo.git/", GitLabPlatform, GitLabPlatform, "https://git.example.test:8443/group/repo"},
		{"https://codeberg.org/org/repo.git", UnknownPlatform, GiteaPlatform, "https://codeberg.org/org/repo"},
		{"https://bitbucket.org/org/repo.git", UnknownPlatform, BitbucketPlatform, "https://bitbucket.org/org/repo"},
		{"https://dev.azure.com/org/project/_git/repo", UnknownPlatform, AzureDevOpsPlatform, "https://dev.azure.com/org/project/_git/repo"},
		{"https://example.test/org/repo.git", UnknownPlatform, UnknownPlatform, "https://example.test/org/repo"},
		{"https://github.com/org/repo.git", NoPlatform, NoPlatform, ""},
		{"/local/repo", GitHubPlatform, GitHubPlatform, ""},
		{"../repo", UnknownPlatform, UnknownPlatform, ""},
		{"C:/local/repo", GitHubPlatform, GitHubPlatform, ""},
		{"file:///local/repo", GitHubPlatform, GitHubPlatform, ""},
		{"https://github.com/%zz", UnknownPlatform, UnknownPlatform, ""},
		{"", UnknownPlatform, UnknownPlatform, ""},
	} {
		t.Run(tc.remote+"/"+tc.platform.String(), func(t *testing.T) {
			platform, remote := ResolveRemoteURL(tc.platform, tc.remote)
			require.Equal(t, tc.want, platform)
			require.Equal(t, tc.url, remote)
		})
	}
}
