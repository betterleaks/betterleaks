package targeturl

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/betterleaks/betterleaks/v2/internal/urlutil"
)

// GitLab is the result of splitting a GitLab URL into its components.
type GitLab struct {
	Scheme string // http or https
	Host   string // hostname[:port]
	Path   string // project/group/user path (everything before "/-/")
	Kind   string // "namespace", "project", "group", "user", "issue", "mr", "snippet", "release", "pipeline", "job"
	ID     string // resource ID (number, tag, snippet id)
}

// ParseGitLab parses a GitLab URL into namespace + optional resource segment.
// At this stage we cannot tell apart project / group / user — `dispatchURL`
// resolves that by querying the API.
func ParseGitLab(rawURL string) (*GitLab, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", urlutil.Error(err))
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("URL must use http or https scheme")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("URL must include a host")
	}

	out := &GitLab{Scheme: u.Scheme, Host: strings.ToLower(u.Host)}

	trimmed := strings.Trim(u.Path, "/")
	if trimmed == "" {
		// Bare host: only valid with explicit AllGroups; caller handles that
		// via the GitLab.AllGroups field. Kind = "namespace" with empty Path
		// signals "instance root".
		out.Kind = "namespace"
		return out, nil
	}

	left, right, hasResource := strings.Cut(trimmed, "/-/")
	out.Path = strings.Trim(left, "/")
	if !hasResource {
		out.Kind = "namespace"
		return out, nil
	}

	parts := strings.Split(strings.Trim(right, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("GitLab resource URL must be .../-/{kind}/{id}")
	}
	kind, id := parts[0], parts[1]
	switch kind {
	case "issues":
		out.Kind = "issue"
		out.ID = id
	case "merge_requests":
		out.Kind = "mr"
		out.ID = id
	case "snippets":
		out.Kind = "snippet"
		out.ID = id
	case "releases":
		out.Kind = "release"
		out.ID = id
	case "pipelines":
		out.Kind = "pipeline"
		out.ID = id
	case "jobs":
		out.Kind = "job"
		out.ID = id
	default:
		return nil, fmt.Errorf("unsupported GitLab URL type %q; supported: issues, merge_requests, snippets, releases, pipelines, jobs", kind)
	}
	return out, nil
}
