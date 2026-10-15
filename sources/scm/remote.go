package scm

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/betterleaks/betterleaks/v2/internal/urlredact"
)

var sshRemote = regexp.MustCompile(`^(?:[^/@:\s]+@)?([a-zA-Z0-9.-]+):(?:\d{1,5}/)?([\w/.-]+?)(?:\.git)?$`)

// ResolveRemoteURL converts a Git fetch URL to a public web URL and infers its
// platform unless explicitly selected. It performs no I/O. Local paths and
// unsupported transports have no web URL; credentials, queries and fragments
// are never included in the result.
func ResolveRemoteURL(platform Platform, remote string) (Platform, string) {
	if platform == NoPlatform {
		return platform, ""
	}
	remote = strings.TrimSpace(remote)
	if !strings.Contains(remote, "://") {
		if m := sshRemote.FindStringSubmatch(remote); m != nil && len(m[1]) > 1 {
			remote = "https://" + m[1] + "/" + m[2]
		}
	}
	u, err := url.Parse(remote)
	if err != nil || u.Hostname() == "" {
		return platform, ""
	}
	switch u.Scheme {
	case "http", "https":
	case "ssh", "git":
		// A transport's port is not the repository browser's HTTPS port.
		u.Scheme, u.Host = "https", u.Hostname()
		if strings.Contains(u.Host, ":") {
			u.Host = "[" + u.Host + "]"
		}
	default:
		return platform, ""
	}
	if platform == UnknownPlatform {
		platform = PlatformFromHost(u.Hostname())
	}
	return platform, strings.TrimSuffix(strings.TrimRight(urlredact.Public(u), "/"), ".git")
}

// PlatformFromHost identifies supported public repository hosts. Private hosts
// need an explicit platform selection.
func PlatformFromHost(host string) Platform {
	switch strings.ToLower(host) {
	case "github.com":
		return GitHubPlatform
	case "gitlab.com":
		return GitLabPlatform
	case "dev.azure.com", "visualstudio.com":
		return AzureDevOpsPlatform
	case "gitea.com", "code.forgejo.org", "codeberg.org":
		return GiteaPlatform
	case "bitbucket.org":
		return BitbucketPlatform
	default:
		return UnknownPlatform
	}
}
