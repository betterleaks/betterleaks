package exprruntime

import "net/http"

// userAgentTransport supplies the provider request default without changing
// caller-owned requests or explicit header values (including an empty value).
type userAgentTransport struct {
	base http.RoundTripper
}

func withDefaultUserAgent(req *http.Request) *http.Request {
	if _, present := req.Header["User-Agent"]; present {
		return req
	}
	clone := req.Clone(req.Context())
	if clone.Header == nil {
		clone.Header = make(http.Header)
	}
	clone.Header.Set("User-Agent", "Betterleaks")
	return clone
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.base.RoundTrip(withDefaultUserAgent(req))
}

func (t *userAgentTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func wrapUserAgentTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if _, ok := base.(*userAgentTransport); ok {
		return base
	}
	return &userAgentTransport{base: base}
}
