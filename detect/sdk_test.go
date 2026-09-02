package detect_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	blregexp "github.com/betterleaks/betterleaks/regexp"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

type fragmentSource struct {
	fragments []sources.Fragment
	err       error
}

func (s fragmentSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	for _, fragment := range s.fragments {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := yield(fragment, nil); err != nil {
			return err
		}
	}
	return s.err
}

func testConfig() *config.Config {
	return &config.Config{Rules: []config.Rule{{
		RuleID: "test-secret",
		Regex:  blregexp.MustCompile(`secret-[a-z]+`),
	}}}
}

func TestDetectorScanIsReusableWithValidation(t *testing.T) {
	cfg := testConfig()
	cfg.Rules[0].ValidateExpr = `{"result": "valid"}`
	detector, err := detect.NewDetector(cfg, detect.WithValidation(detect.ValidationOptions{
		Workers:  1,
		Statuses: []report.ValidationStatus{report.ValidationStatusValid},
	}))
	require.NoError(t, err)
	require.True(t, detector.ValidationEnabled())

	const content = "secret-alpha"
	for range 2 {
		var findings []report.Finding
		summary, scanErr := detector.Scan(t.Context(), fragmentSource{fragments: []sources.Fragment{{Raw: content}}}, func(finding report.Finding) error {
			findings = append(findings, finding)
			return nil
		})
		require.NoError(t, scanErr)
		require.Len(t, findings, 1)
		assert.Equal(t, report.ValidationStatusValid, findings[0].Validation.Status)
		assert.Equal(t, uint64(len(content)), summary.BytesInspected)
		assert.Equal(t, 1, summary.Findings)
		assert.Equal(t, 1, summary.ValidationCounts[report.ValidationStatusValid])
	}
}

func TestValidationRequiresExplicitOption(t *testing.T) {
	cfg := testConfig()
	cfg.Rules[0].ValidateExpr = `{"result": "valid"}`

	detector, err := detect.NewDetector(cfg)
	require.NoError(t, err)
	assert.False(t, detector.ValidationEnabled())

	detector, err = detect.NewDetector(cfg, detect.WithValidation(detect.ValidationOptions{}))
	require.NoError(t, err)
	assert.True(t, detector.ValidationEnabled())
}

func TestAnalysisRequiresExplicitOptionAndImpliesValidation(t *testing.T) {
	cfg := testConfig()
	cfg.Rules[0].ValidateExpr = `{"result": "valid", "owner": "user-1"}`
	cfg.Rules[0].AnalyzeExpr = `{
		"identity": {"id": validation["metadata"]["owner"]},
		"capabilities": ["read"]
	}`

	detector, err := detect.NewDetector(cfg)
	require.NoError(t, err)
	assert.False(t, detector.ValidationEnabled())
	assert.False(t, detector.AnalysisEnabled())

	detector, err = detect.NewDetector(cfg, detect.WithValidation(detect.ProviderOptions{}))
	require.NoError(t, err)
	assert.True(t, detector.ValidationEnabled())
	assert.False(t, detector.AnalysisEnabled())

	detector, err = detect.NewDetector(cfg, detect.WithAnalysis(detect.ProviderOptions{Workers: 1}))
	require.NoError(t, err)
	assert.True(t, detector.ValidationEnabled())
	assert.True(t, detector.AnalysisEnabled())

	var findings []report.Finding
	_, scanErr := detector.Scan(t.Context(), fragmentSource{fragments: []sources.Fragment{{Raw: "secret-alpha"}}}, func(finding report.Finding) error {
		findings = append(findings, finding)
		return nil
	})
	require.NoError(t, scanErr)
	require.Len(t, findings, 1)
	assert.Equal(t, report.ValidationStatusValid, findings[0].Validation.Status)
	assert.Equal(t, report.SeverityMedium, findings[0].Analysis.Severity)
	require.NotNil(t, findings[0].Analysis.Identity)
	assert.Equal(t, "user-1", findings[0].Analysis.Identity.ID)
}

func TestDetectorSkipFunc(t *testing.T) {
	cfg := testConfig()
	cfg.Prefilter = `attributes["path"] == "ignored.txt"`
	detector, err := detect.NewDetector(cfg)
	require.NoError(t, err)

	skip := detector.SkipFunc()
	require.NotNil(t, skip)
	assert.True(t, skip(map[string]string{sources.AttrPath: "ignored.txt"}))
	assert.False(t, skip(map[string]string{sources.AttrPath: "kept.txt"}))
}

func TestDetectorScanReturnsHandlerAndSourceErrors(t *testing.T) {
	detector, err := detect.NewDetector(testConfig())
	require.NoError(t, err)

	handlerErr := errors.New("store finding")
	summary, scanErr := detector.Scan(t.Context(), fragmentSource{fragments: []sources.Fragment{{Raw: "secret-alpha"}}}, func(report.Finding) error {
		return handlerErr
	})
	assert.ErrorIs(t, scanErr, handlerErr)
	assert.Equal(t, 1, summary.Findings)

	sourceErr := errors.New("read source")
	_, scanErr = detector.Scan(t.Context(), fragmentSource{err: sourceErr}, nil)
	assert.ErrorIs(t, scanErr, sourceErr)
}

func TestWithPrecompileIsTheEagerCompilationPath(t *testing.T) {
	cfg := testConfig()
	cfg.Filter = `missingFunction()`

	_, err := detect.NewDetector(cfg)
	require.NoError(t, err, "expressions remain lazy by default")

	_, err = detect.NewDetector(cfg, detect.WithPrecompile())
	require.ErrorContains(t, err, "compiling global filter")

	cfg = testConfig()
	cfg.Rules[0].ValidateExpr = `missingFunction()`
	_, err = detect.NewDetector(cfg, detect.WithPrecompile())
	require.ErrorContains(t, err, "validation")
}

func TestNewDetectorValidatesOptions(t *testing.T) {
	_, err := detect.NewDetector(nil)
	assert.Error(t, err)

	_, err = detect.NewDetector(testConfig(), detect.WithJobs(-1))
	assert.ErrorContains(t, err, "jobs")

	_, err = detect.NewDetector(testConfig(), detect.WithMatchContext("bad"))
	assert.ErrorContains(t, err, "match context")

	_, err = detect.NewDetector(testConfig(), detect.WithValidation(detect.ValidationOptions{
		Statuses: []report.ValidationStatus{"surprising"},
	}))
	assert.ErrorContains(t, err, "invalid validation status")
}

func ExampleDetector_Scan() {
	cfg := &config.Config{Rules: []config.Rule{{
		RuleID: "test-secret",
		Regex:  blregexp.MustCompile(`secret-[a-z]+`),
	}}}
	detector, err := detect.NewDetector(cfg, detect.WithJobs(2))
	if err != nil {
		panic(err)
	}
	source := &sources.Stdin{Content: strings.NewReader("secret-alpha")}
	summary, err := detector.Scan(context.Background(), source, func(finding report.Finding) error {
		fmt.Println(finding.RuleID)
		return nil
	})
	fmt.Println(summary.Findings, err)

	// Output:
	// test-secret
	// 1 <nil>
}
