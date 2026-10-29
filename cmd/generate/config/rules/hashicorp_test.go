package rules

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
)

func TestHashicorpFieldTerraformVariableDefaults(t *testing.T) {
	const longPassword = "A1b2C3d4E5f6G7h8I9j0K1l2M3"
	require.Len(t, longPassword, 26)

	rule := HashicorpField()
	scanner, err := scan.New(&config.Config{Rules: []config.Rule{*rule}})
	require.NoError(t, err)

	tests := []struct {
		name       string
		path       string
		content    string
		wantValues []string
	}{
		{
			name: "multiline password variable default",
			path: "variables.tf",
			content: `variable "password" {
  type    = string
  default = "` + longPassword + `"
}`,
			wantValues: []string{`"` + longPassword + `"`},
		},
		{
			name: "reported Terraform snippet",
			path: "variables.tf",
			content: `variable "password" {
  type        = string
  default     = "693cb103178f5ac67ccc56a349"
  description = "Password for the application"
}`,
			wantValues: []string{`"693cb103178f5ac67ccc56a349"`},
		},
		{
			name: "low entropy variable default",
			path: "variables.tf",
			content: `variable "password" {
  default = "abcdabcd"
}`,
			wantValues: []string{`"abcdabcd"`},
		},
		{
			name: "nested braces and braces in strings and comments",
			path: "variables.tf",
			content: `variable "password" {
  description = "closing brace } inside a string"
  type = object({ settings = object({ enabled = bool }) })
  validation {
    condition     = length(var.password) > 0
    error_message = "opening brace { inside a string"
  }
  # closing brace } inside a comment
  default = "nestedSecret123"
}`,
			wantValues: []string{`"nestedSecret123"`},
		},
		{
			name:       "password variable in hcl",
			path:       "variables.hcl",
			content:    "variable \"password\" {\n  default = \"rootpasswd\"\n}",
			wantValues: []string{`"rootpasswd"`},
		},
		{
			name:       "windows line endings",
			path:       "variables.tf",
			content:    "variable \"password\" {\r\n  default = \"rootpasswd\"\r\n}",
			wantValues: []string{`"rootpasswd"`},
		},
		{
			name:       "existing inline assignment",
			path:       "variables.tf",
			content:    "administrator_login_password = \"thisIsDog11\"",
			wantValues: []string{`"thisIsDog11"`},
		},
		{
			name:    "non-password variable",
			path:    "variables.tf",
			content: "variable \"username\" {\n  default = \"rootpasswd\"\n}",
		},
		{
			name:    "expression default",
			path:    "variables.tf",
			content: "variable \"password\" {\n  default = var.db_password\n}",
		},
		{
			name:    "interpolated expression default",
			path:    "variables.tf",
			content: "variable \"password\" {\n  default = \"${var.db_password}\"\n}",
		},
		{
			name:    "non-terraform path",
			path:    "variables.yaml",
			content: "variable \"password\" {\n  default = \"rootpasswd\"\n}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var findings []report.Finding
			summary, err := scanner.Scan(t.Context(), &sources.Reader{
				Content: strings.NewReader(tt.content),
				Attributes: map[string]string{
					sources.AttrPath: tt.path,
				},
			}, func(finding report.Finding) error {
				findings = append(findings, finding)
				return nil
			})
			require.NoError(t, err)
			require.Equal(t, len(tt.wantValues), summary.Findings)
			require.Len(t, findings, len(tt.wantValues))
			for i, value := range tt.wantValues {
				require.Equal(t, value, findings[i].Match.Value)
			}
		})
	}
}

func TestDefaultConfigDetectsTerraformVariableDefault(t *testing.T) {
	cfg, err := config.Default()
	require.NoError(t, err)
	scanner, err := scan.New(cfg)
	require.NoError(t, err)

	var findings []report.Finding
	summary, err := scanner.Scan(t.Context(), &sources.Reader{
		Content: strings.NewReader(`variable "password" {
  validation {
    condition = length(var.password) > 0
  }
  default = "abcdabcd"
}`),
		Attributes: map[string]string{
			sources.AttrPath: "variables.tf",
		},
	}, func(finding report.Finding) error {
		if finding.RuleID == "hashicorp-tf-password" {
			findings = append(findings, finding)
		}
		return nil
	})
	require.NoError(t, err)
	require.GreaterOrEqual(t, summary.Findings, 1)
	require.Len(t, findings, 1)
	require.Equal(t, `"abcdabcd"`, findings[0].Match.Value)
}
