package exprruntime

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnalysisReceivesValidationBinding(t *testing.T) {
	runtime, err := New(nil)
	require.NoError(t, err)
	program, err := runtime.CompileAnalysis(`let scopes = validation.analysis["scopes"] ?? []; {
		"identity": {"id": validation.analysis["owner"]},
		"capabilities": analysis.capabilities({
			"read": validation["status"] == "valid" && filter.matchesAny(scopes, ["^read_"]),
			"write": filter.intersects(scopes, ["write_api"])
		})
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
			"metadata": map[string]any{},
			"analysis": map[string]any{"owner": "user-1", "scopes": []string{"read_api", "write_api"}},
		},
		EvalOptions{},
	)
	require.NoError(t, err)
	value := result.Value.(map[string]any)
	assert.Equal(t, "user-1", value["identity"].(map[string]any)["id"])
	assert.Equal(t, []string{"read", "write"}, value["capabilities"])
}

func TestAnalysisRejectsInvalidRegexPattern(t *testing.T) {
	runtime, err := New(nil)
	require.NoError(t, err)
	program, err := runtime.CompileAnalysis(`filter.matchesAny(["read_api"], ["*read"])`)
	require.NoError(t, err)

	_, err = runtime.EvalAnalysisWithComponents(
		t.Context(),
		program,
		map[string]string{"secret": "token", "rule_id": "test"},
		nil,
		nil,
		nil,
		nil,
		EvalOptions{},
	)
	require.ErrorContains(t, err, `invalid regex pattern "*read"`)
}
