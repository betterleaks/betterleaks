package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/report"
)

func reportTestCommand(path, format, template string) *cobra.Command {
	cmd := new(cobra.Command)
	cmd.Flags().String("report-path", path, "")
	cmd.Flags().String("report-format", format, "")
	cmd.Flags().String("report-template", template, "")
	return cmd
}

func TestWriteFindingsReportInfersJSONFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.json")
	cmd := reportTestCommand(path, "", "")
	findings := []report.Finding{{RuleID: "example", Secret: "secret"}}

	require.NoError(t, writeFindingsReport(cmd, &config.Config{}, findings))
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(contents), `"RuleID": "example"`)
}

func TestWriteFindingsReportTemplateImpliesFormat(t *testing.T) {
	dir := t.TempDir()
	templatePath := filepath.Join(dir, "report.tmpl")
	require.NoError(t, os.WriteFile(templatePath, []byte(`{{ len . }}`), 0o600))
	reportPath := filepath.Join(dir, "report.txt")
	cmd := reportTestCommand(reportPath, "", templatePath)

	require.NoError(t, writeFindingsReport(cmd, &config.Config{}, []report.Finding{{}}))
	contents, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	require.Equal(t, "1", string(contents))
}

func TestWriteFindingsReportRejectsTemplateFormatMismatch(t *testing.T) {
	cmd := reportTestCommand(filepath.Join(t.TempDir(), "report.json"), "json", "report.tmpl")
	err := writeFindingsReport(cmd, &config.Config{}, nil)
	require.EqualError(t, err, "report format must be 'template' if --report-template is specified")
}

func TestResolveFindingsReportDoesNotTouchOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.json")
	require.NoError(t, os.WriteFile(path, []byte("keep me"), 0o600))
	cmd := reportTestCommand(path, "json", "")

	resolved, err := resolveFindingsReport(cmd, &config.Config{})
	require.NoError(t, err)
	require.NotNil(t, resolved)
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "keep me", string(contents))
}

func TestResolveFindingsReportValidatesTemplateBeforeWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.txt")
	cmd := reportTestCommand(path, "template", filepath.Join(t.TempDir(), "missing.tmpl"))

	resolved, err := resolveFindingsReport(cmd, &config.Config{})
	require.Nil(t, resolved)
	require.ErrorContains(t, err, "invalid report template")
	_, statErr := os.Stat(path)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}
