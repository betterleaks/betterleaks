package analyze

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/report"
)

func TestParseResultNormalizesCapabilitiesAndIdentity(t *testing.T) {
	result, err := ParseResult(map[string]any{
		"identity": map[string]any{
			"id": " user-1 ",
			"account": map[string]any{
				"name":    " Acme ",
				"domains": []any{"example.org", "", "example.com", "example.org"},
			},
		},
		"capabilities": []any{"admin", "read", "write", "read"},
		"metadata": map[string]any{
			"notes": []any{" Limited to this account. ", "", "Limited to this account.", "Other grants were not inspected."},
			"permissions": []any{map[string]any{
				"access":      "user",
				"permissions": []any{"read_job"},
			}},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"Limited to this account.", "Other grants were not inspected."}, result.Metadata["notes"])
	assert.Equal(t, report.SeverityHigh, result.Severity)
	assert.Equal(t, []report.Capability{
		report.CapabilityRead,
		report.CapabilityWrite,
		report.CapabilityAdmin,
	}, result.Capabilities)
	assert.Equal(t, []any{map[string]any{
		"access":      "user",
		"permissions": []any{"read_job"},
	}}, result.Metadata["permissions"])
	require.NotNil(t, result.Identity)
	assert.Equal(t, "user-1", result.Identity.ID)
	require.NotNil(t, result.Identity.Account)
	assert.Equal(t, "Acme", result.Identity.Account.Name)
	assert.Equal(t, []string{"example.com", "example.org"}, result.Identity.Account.Domains)
}

func TestParseResultDerivesSeverity(t *testing.T) {
	tests := []struct {
		name         string
		capabilities []any
		want         report.Severity
	}{
		{name: "none", want: report.SeverityUnknown},
		{name: "read", capabilities: []any{"read"}, want: report.SeverityMedium},
		{name: "write", capabilities: []any{"write"}, want: report.SeverityHigh},
		{name: "write then read", capabilities: []any{"write", "read"}, want: report.SeverityHigh},
		{name: "read then write", capabilities: []any{"read", "write"}, want: report.SeverityHigh},
		{name: "secrets", capabilities: []any{"read_secrets"}, want: report.SeverityHigh},
		{name: "credentials", capabilities: []any{"create_credentials"}, want: report.SeverityHigh},
		{name: "users", capabilities: []any{"manage_users"}, want: report.SeverityHigh},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := ParseResult(map[string]any{
				"capabilities": test.capabilities,
			})
			require.NoError(t, err)
			assert.Equal(t, test.want, result.Severity)
		})
	}
}

func TestParseResultWithoutCapabilityEvidence(t *testing.T) {
	for _, value := range []map[string]any{
		{},
		{"capabilities": []any{}},
		{"capabilities": nil},
		{"metadata": map[string]any{"notes": []string{"Could not determine permissions"}}},
		{"identity": map[string]any{"id": "user-1"}},
		{"metadata": map[string]any{"plan": "enterprise"}},
	} {
		result, err := ParseResult(value)
		require.NoError(t, err)
		assert.Equal(t, report.SeverityUnknown, result.Severity)
		assert.False(t, result.IsZero(), "analysis ran even though permissions are unknown")
	}
	assert.True(t, (report.Analysis{}).IsZero(), "analysis that never ran remains absent")
}

func TestParseResultRejectsUnknownSchema(t *testing.T) {
	_, err := ParseResult(map[string]any{"severity": "high"})
	require.ErrorContains(t, err, `unknown field "severity"`)

	_, err = ParseResult(map[string]any{"capabilities": []any{"delete_everything"}})
	require.ErrorContains(t, err, `unknown analysis capability "delete_everything"`)

	_, err = ParseResult(map[string]any{"status": "complete"})
	require.ErrorContains(t, err, `unknown field "status"`)

	_, err = ParseResult(map[string]any{"metadata": []any{"scope"}})
	require.ErrorContains(t, err, "analysis metadata must be an object")

	_, err = ParseResult(map[string]any{"reason": "Ambiguous explanation"})
	require.ErrorContains(t, err, `unknown field "reason"`)

	for _, metadata := range []map[string]any{
		{"notes": "a note"}, {"notes": []any{123}}, {"notes": nil},
		{"analysis_error": "spoofed runtime failure"},
	} {
		_, err := ParseResult(map[string]any{"metadata": metadata})
		require.Error(t, err)
	}
}

func TestParseResultNotesDoNotMutateProviderEvidence(t *testing.T) {
	for _, notes := range []any{[]string{}, []any{"", "  "}} {
		metadata := map[string]any{"notes": notes, "project_id": "project-1"}
		result, err := ParseResult(map[string]any{"metadata": metadata})
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"project_id": "project-1"}, result.Metadata)
		assert.Equal(t, notes, metadata["notes"])
	}
}
