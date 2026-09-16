package targeturl

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/betterleaks/betterleaks/v2/internal/urlutil"
)

type HuggingFace struct {
	Scheme string
	Host   string
	Kind   string // "owner", "repo", or "bucket"
	Owner  string
	Name   string
	Type   string
	Prefix string
}

func ParseHuggingFace(rawURL string) (*HuggingFace, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", urlutil.Error(err))
	}
	if u.Scheme == "hf" {
		segments := PathSegments(u.Host + "/" + u.Path)
		if len(segments) < 3 || segments[0] != "buckets" {
			return nil, fmt.Errorf("hf:// URL must use hf://buckets/<owner>/<bucket>[/prefix]")
		}
		return &HuggingFace{
			Scheme: "hf",
			Host:   "buckets",
			Kind:   "bucket",
			Owner:  segments[1],
			Name:   segments[2],
			Prefix: strings.Join(segments[3:], "/"),
		}, nil
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("URL must use http or https scheme")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("URL must include a host")
	}
	segments := PathSegments(u.Path)
	out := &HuggingFace{Scheme: u.Scheme, Host: strings.ToLower(u.Host)}
	switch {
	case len(segments) >= 3 && segments[0] == "buckets":
		out.Kind = "bucket"
		out.Owner = segments[1]
		out.Name = segments[2]
		out.Prefix = strings.Join(segments[3:], "/")
		return out, nil
	case len(segments) == 1:
		out.Kind = "owner"
		out.Owner = segments[0]
		return out, nil
	case len(segments) == 3 && segments[0] == "datasets":
		out.Kind = "repo"
		out.Type = "dataset"
		out.Owner = segments[1]
		out.Name = strings.TrimSuffix(segments[2], ".git")
	case len(segments) == 3 && segments[0] == "spaces":
		out.Kind = "repo"
		out.Type = "space"
		out.Owner = segments[1]
		out.Name = strings.TrimSuffix(segments[2], ".git")
	case len(segments) == 2:
		out.Kind = "repo"
		out.Type = "model"
		out.Owner = segments[0]
		out.Name = strings.TrimSuffix(segments[1], ".git")
	default:
		return nil, fmt.Errorf("Hugging Face URL must identify an owner or repository")
	}
	if out.Owner == "" || out.Name == "" {
		return nil, fmt.Errorf("Hugging Face repository URL must include owner and name")
	}
	return out, nil
}

func PathSegments(p string) []string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	out := parts[:0]
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
