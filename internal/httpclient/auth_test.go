package httpclient

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewAuthenticatedClient_setsBearerOnAllowedHost(t *testing.T) {
	t.Parallel()
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	u := srv.URL // e.g. http://127.0.0.1:12345
	host := strings.TrimPrefix(strings.TrimPrefix(u, "http://"), "https://")
	cli := NewAuthenticatedClient("secret", http.DefaultTransport, host)

	req, err := http.NewRequest(http.MethodGet, u+"/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotAuth != "Bearer secret" {
		t.Fatalf("Authorization = %q, want Bearer secret", gotAuth)
	}
}

func TestNewAuthenticatedClient_noBearerOnForeignHost(t *testing.T) {
	t.Parallel()
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	cli := NewAuthenticatedClient("secret", http.DefaultTransport, "api.github.com")

	resp, err := cli.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if gotAuth != "" {
		t.Fatalf("Authorization leaked to foreign host: %q", gotAuth)
	}
}

func TestNewAuthenticatedClient_emptyTokenNoAuth(t *testing.T) {
	t.Parallel()
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	host := strings.TrimPrefix(strings.TrimPrefix(srv.URL, "http://"), "https://")
	cli := NewAuthenticatedClient("", http.DefaultTransport, host)

	resp, err := cli.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotAuth != "" {
		t.Fatalf("unexpected Authorization: %q", gotAuth)
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
