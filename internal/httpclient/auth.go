package httpclient

import (
	"net/http"
	"net/url"
	"strings"
)

// NewAuthenticatedClient returns an HTTP client that adds a Bearer token only
// when the request URL's host matches one of allowedHosts (case-insensitive;
// port in allowedHosts entries is ignored; request hosts are compared via
// URL.Hostname()).
//
// When token is empty, or no allowedHosts remain after normalization, it
// returns a client with only base (no Authorization injection), avoiding
// accidentally leaking credentials to unrelated hosts (e.g. release-asset CDNs).
//
// When base is nil, it uses [http.DefaultTransport].
func NewAuthenticatedClient(token string, base http.RoundTripper, allowedHosts ...string) *http.Client {
	if token == "" {
		if base == nil {
			return &http.Client{}
		}
		return &http.Client{Transport: base}
	}
	allow := make(map[string]struct{})
	for _, h := range allowedHosts {
		k := normalizeAllowHost(h)
		if k != "" {
			allow[k] = struct{}{}
		}
	}
	if len(allow) == 0 {
		if base == nil {
			return &http.Client{}
		}
		return &http.Client{Transport: base}
	}
	return &http.Client{Transport: &hostScopedAuthTransport{
		token:   token,
		base:    base,
		allowed: allow,
	}}
}

type hostScopedAuthTransport struct {
	token   string
	base    http.RoundTripper
	allowed map[string]struct{}
}

func (t *hostScopedAuthTransport) underlying() http.RoundTripper {
	if t.base != nil {
		return t.base
	}
	return http.DefaultTransport
}

func (t *hostScopedAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.allowed == nil || req.URL == nil {
		return t.underlying().RoundTrip(req)
	}
	host := strings.ToLower(req.URL.Hostname())
	if _, ok := t.allowed[host]; !ok {
		return t.underlying().RoundTrip(req)
	}
	req2 := req.Clone(req.Context())
	req2.Header.Set("Authorization", "Bearer "+t.token)
	return t.underlying().RoundTrip(req2)
}

// normalizeAllowHost lowercases a host string for allowlist lookup.
// Values may be bare "host", "host:port", or a full URL with a scheme.
func normalizeAllowHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if strings.Contains(h, "://") {
		u, err := url.Parse(h)
		if err != nil {
			return ""
		}
		return strings.ToLower(u.Hostname())
	}
	u := &url.URL{Host: h}
	return strings.ToLower(u.Hostname())
}
