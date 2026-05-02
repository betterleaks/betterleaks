package httpclient

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

// NewAuthenticatedClient builds an OAuth2-backed HTTP client when token is set.
// When token is empty it returns a client using the provided base transport.
func NewAuthenticatedClient(_ context.Context, token string, base http.RoundTripper) *http.Client {
	if token == "" {
		if base == nil {
			return nil
		}
		return &http.Client{Transport: base}
	}
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	return &http.Client{Transport: &oauth2.Transport{Source: ts, Base: base}}
}
