package exprruntime

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnalysisReceivesValidationBinding(t *testing.T) {
	runtime, err := New(nil)
	require.NoError(t, err)
	program, err := runtime.CompileAnalysis(`{
		"identity": {"id": validation["metadata"]["owner"]},
		"capabilities": validation["status"] == "valid" ? ["read"] : []
	}`)
	require.NoError(t, err)

	result, err := runtime.EvalAnalysisWithComponents(
		t.Context(),
		program,
		map[string]string{"secret": "token", "rule_id": "test"},
		nil,
		nil,
		nil,
		map[string]any{
			"status":   "valid",
			"reason":   "",
			"metadata": map[string]any{"owner": "user-1"},
		},
		EvalOptions{},
	)
	require.NoError(t, err)
	value := result.Value.(map[string]any)
	assert.Equal(t, "user-1", value["identity"].(map[string]any)["id"])
}
