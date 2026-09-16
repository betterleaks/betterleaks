package targeturl

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/betterleaks/betterleaks/v2/internal/urlutil"
)

// GitHub holds the components extracted from a GitHub target URL.
type GitHub struct {
	Owner    string // repo owner, org name, user name, or gist user
	Repo     string // repo name (empty for owner-level or gists)
	Resource string // "owner", "repo", "issue", "pr", "actions_run", "release", "discussion", "gist"
	ID       string // number, run ID, tag name, or gist ID (empty for owner/repo targets)
	Host     string // host (for GHE detection)
}

// ParseGitHub parses a GitHub URL into its components.
// Supports org/user URLs, repo URLs, specific resource URLs, and gists.
func ParseGitHub(rawURL string) (*GitHub, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", urlutil.Error(err))
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("URL must use http or https scheme")
	}

	host := strings.ToLower(u.Host)

	// Gist: gist.github.com/{user}/{id} or gist.{ghe-host}/{user}/{id}
	if strings.HasPrefix(host, "gist.") {
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("gist URL must be gist.github.com/{user}/{id}")
		}
		return &GitHub{Owner: parts[0], Resource: "gist", ID: parts[1], Host: host}, nil
	}

	parts := strings.Split(strings.Trim(u.Path, "/"), "/")

	// Owner-level URL: github.com/{owner}
	if len(parts) == 1 && parts[0] != "" {
		return &GitHub{Owner: parts[0], Resource: "owner", Host: host}, nil
	}

	// Repo-level URL: github.com/{owner}/{repo}
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return &GitHub{Owner: parts[0], Repo: parts[1], Resource: "repo", Host: host}, nil
	}

	// Specific resource: {host}/{owner}/{repo}/{type}/...
	if len(parts) < 4 {
		return nil, fmt.Errorf("URL must point to a GitHub owner, repo, or specific resource (issue, PR, discussion, release, or action run)")
	}
	owner, repo := parts[0], parts[1]
	kind, id := parts[2], parts[3]

	p := &GitHub{Owner: owner, Repo: repo, Host: host}

	switch kind {
	case "issues":
		p.Resource = "issue"
		p.ID = id
	case "pull":
		p.Resource = "pr"
		p.ID = id
	case "discussions":
		p.Resource = "discussion"
		p.ID = id
	case "releases":
		// releases/tag/{tag}
		if id != "tag" || len(parts) < 5 || parts[4] == "" {
			return nil, fmt.Errorf("release URL must be .../releases/tag/{tag}")
		}
		p.Resource = "release"
		p.ID = parts[4]
	case "actions":
		// actions/runs/{id} or actions/runs/{id}/job/{jobId}
		if id != "runs" || len(parts) < 5 || parts[4] == "" {
			return nil, fmt.Errorf("actions URL must be .../actions/runs/{id}")
		}
		p.Resource = "actions_run"
		p.ID = parts[4]
	default:
		return nil, fmt.Errorf("unsupported GitHub URL type %q; supported: issues, pull, discussions, releases/tag, actions/runs, gist", kind)
	}

	return p, nil
}
