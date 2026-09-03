package exprruntime

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnalysisCapabilities(t *testing.T) {
	got, err := analysisCapabilities(map[string]any{
		"admin": false,
		"write": true,
		"read":  true,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"read", "write"}, got)
}

func TestAnalysisCapabilitiesRejectsInvalidConditions(t *testing.T) {
	_, err := analysisCapabilities(map[string]any{"root": true})
	require.ErrorContains(t, err, `unknown capability "root"`)

	_, err = analysisCapabilities(map[string]any{"read": "yes"})
	require.ErrorContains(t, err, `"read" must be a boolean`)
}

func TestAnalysisNamespaceContainsAnalysisHelpers(t *testing.T) {
	namespace := analysisNamespace()
	assert.Contains(t, namespace, "capabilities")
	assert.NotContains(t, namespace, "metadata")
	assert.NotContains(t, namespace, "scopes")
}
