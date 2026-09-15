package exprruntime

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRevocationProgramsRequireExplicitEvaluation(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	runtime, err := New(nil)
	require.NoError(t, err)
	program, err := runtime.CompileRevocation(fmt.Sprintf(`http.delete(%q, {})`, server.URL))
	require.NoError(t, err)
	require.Zero(t, requests.Load(), "compiling must not execute the program")
	finding := map[string]string{"secret": "secret", "rule_id": "rule"}
	_, err = runtime.EvalValidation(t.Context(), program, finding, nil, nil, EvalOptions{})
	require.ErrorContains(t, err, "explicit revocation")
	_, err = runtime.EvalAnalysisWithComponents(t.Context(), program, finding, nil, nil, nil, nil, EvalOptions{})
	require.ErrorContains(t, err, "explicit revocation")
	require.Zero(t, requests.Load())
	_, err = runtime.EvalRevocationWithComponents(t.Context(), program, finding, nil, nil, EvalOptions{})
	require.NoError(t, err)
	require.EqualValues(t, 1, requests.Load())

	_, err = runtime.CompileValidation(`http.delete("https://example.test", {})`)
	require.Error(t, err)
	_, err = runtime.CompileAnalysis(`http.delete("https://example.test", {})`)
	require.Error(t, err)
	for _, expression := range []string{`finding.match`, `attributes.path`, `validation.status`} {
		_, err := runtime.CompileRevocation(expression)
		require.Error(t, err, expression)
	}
}
