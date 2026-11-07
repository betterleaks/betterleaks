package exprruntime

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProviderUserAgent(t *testing.T) {
	for _, tc := range []struct{ name, headers, want string }{
		{"default", `{}`, "Betterleaks"},
		{"override", `{"user-agent": "custom-agent"}`, "custom-agent"},
		{"empty", `{"User-Agent": ""}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.UserAgent(); got != tc.want {
					t.Errorf("User-Agent = %q, want %q", got, tc.want)
				}
				if r.URL.Path == "/redirect" {
					http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
					return
				}
				fmt.Fprint(w, "ok")
			}))
			defer server.Close()
			for _, client := range []*http.Client{nil, server.Client()} {
				rt, err := New(client)
				require.NoError(t, err)
				for _, compile := range []func(string) (Program, error){rt.CompileValidation, rt.CompileAnalysis} {
					for _, expr := range []string{
						fmt.Sprintf(`http.get(%q, %s).status`, server.URL+"/redirect", tc.headers),
						fmt.Sprintf(`http.post(%q, %s, "payload").status`, server.URL+"/redirect", tc.headers),
					} {
						prg, err := compile(expr)
						require.NoError(t, err)
						got, err := rt.Eval(prg, nil, nil)
						require.NoError(t, err)
						require.Equal(t, int64(http.StatusOK), got)
					}
				}
			}
		})
	}
}

func TestUserAgentClientReconfiguration(t *testing.T) {
	calls := 0
	base := validationRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		require.Equal(t, "Betterleaks", req.UserAgent())
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header)}, nil
	})
	client := &http.Client{Transport: base, Timeout: time.Second}
	rt, err := New(client)
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		require.NoError(t, rt.SetValidationRequestLimits(ValidationRequestLimits{MaxRequestsPerTarget: 1}))
		rt.SetHTTPClient(client)
		req, err := http.NewRequest(http.MethodGet, "https://example.test", nil)
		require.NoError(t, err)
		resp, err := rt.client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		require.Empty(t, req.Header, "must not mutate caller-owned headers")
		_, err = rt.client.Do(req)
		require.Error(t, err, "request limit must survive client replacement")
		require.NoError(t, rt.SetValidationRequestLimits(ValidationRequestLimits{}))
		require.Equal(t, time.Second, rt.client.Timeout)
		resp, err = rt.client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
	}
	require.Equal(t, 4, calls)
	require.Equal(t, time.Second, client.Timeout)
	_, wrapped := client.Transport.(*userAgentTransport)
	require.False(t, wrapped, "must not mutate caller-owned client")
}
