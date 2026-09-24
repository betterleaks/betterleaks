package httpclient

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthenticatedClient(t *testing.T) {
	for _, tc := range []struct {
		name, token, want string
		foreignHost       bool
	}{
		{"allowed host", "secret", "Bearer secret", false},
		{"foreign host", "secret", "", true},
		{"empty token", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Echo the header so assertions run in the test goroutine.
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, r.Header.Get("Authorization"))
			}))
			defer server.Close()
			host := strings.TrimPrefix(server.URL, "http://")
			if tc.foreignHost {
				host = "api.github.com"
			}
			client := NewAuthenticatedClient(tc.token, http.DefaultTransport, host)
			response, err := client.Get(server.URL + "/x")
			require.NoError(t, err)
			defer response.Body.Close()
			got, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			require.Equal(t, tc.want, string(got))
		})
	}
}

func TestNormalizeAllowHost(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
	}{
		{"api.github.com", "api.github.com"},
		{"API.GITHUB.COM", "api.github.com"},
		{"api.github.com:443", "api.github.com"},
		{"https://ghe.example/api/v3", "ghe.example"},
		{"", ""},
		{"   ", ""},
	}
	for _, tc := range tests {
		got := normalizeAllowHost(tc.in)
		if got != tc.want {
			t.Errorf("normalizeAllowHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
