package provider

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/stretchr/testify/require"
)

func TestProviderDebugIsRedactedInFinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, r.Body)
	}))
	t.Cleanup(server.Close)
	runtime, err := exprruntime.New(server.Client())
	require.NoError(t, err)
	program, err := runtime.CompileValidation(fmt.Sprintf(`
		let response = http.post(%q + "?token=" + finding["secret"], {}, finding["secret"]);
		{"result": "valid", "reason": response.body}
	`, server.URL))
	require.NoError(t, err)
	pool := NewPoolContext(t.Context(), 1, runtime)
	pool.Debug = true
	results := make(chan report.Finding, 1)
	pool.Emit = func(f report.Finding) { results <- f }
	const secret = "synthetic-debug-credential"
	require.NoError(t, pool.SubmitContext(t.Context(), report.Finding{
		RuleID: "debug-test", Secret: secret,
	}, program))
	pool.Close()
	finding := <-results
	require.Equal(t, report.ValidationStatusValid, finding.Validation.Status)
	require.Contains(t, finding.Validation.Metadata["req_url"], secret)
	require.Equal(t, secret, finding.Validation.Metadata["req_body"])
	require.Equal(t, secret, finding.Validation.Metadata["resp_body"])
	redacted := finding.RedactedCopy(100)
	encoded, err := json.Marshal(redacted)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), secret)
	require.Equal(t, "[redacted]", redacted.Validation.Reason)
}
