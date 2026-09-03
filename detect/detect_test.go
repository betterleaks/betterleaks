package detect

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/detect/codec"
	"github.com/betterleaks/betterleaks/v2/internal/contextwindow"
	"github.com/betterleaks/betterleaks/v2/internal/ruletiming"
	"github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/scm"
)

const maxDecodeDepth = 8
const configPath = "../testdata/config/"
const repoBasePath = "../testdata/repos/"
const archivesBasePath = "../testdata/archives/"

type cancelOnSecondCheck struct {
	checks int
	open   chan struct{}
	closed chan struct{}
}

type repeatedFragmentSource struct {
	count int
}

type fragmentSource struct {
	fragments []sources.Fragment
	err       error
}

func (s repeatedFragmentSource) Fragments(_ context.Context, yield sources.FragmentsFunc) error {
	for range s.count {
		if err := yield(sources.Fragment{Raw: "ghp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"}, nil); err != nil {
			return err
		}
	}
	return nil
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

type cancelAwareSource struct {
	stopped chan struct{}
}

func (s cancelAwareSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	defer close(s.stopped)
	if err := yield(sources.Fragment{Raw: "ghp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"}, nil); err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}

func newCancelOnSecondCheck() *cancelOnSecondCheck {
	closed := make(chan struct{})
	close(closed)
	return &cancelOnSecondCheck{open: make(chan struct{}), closed: closed}
}

func normalizeFindings(fs []report.Finding) {
	// TODO: Temporary mitigation.
	// https://github.com/gitleaks/gitleaks/issues/1641
	for i := 0; i < len(fs); i++ {
		f := &fs[i]
		f.Line = strings.ReplaceAll(f.Line, "\r", "")
		before := len(f.Match)
		f.Match = strings.ReplaceAll(f.Match, "\r", "")
		after := len(f.Match)
		f.Location.EndColumn -= before - after
	}
}

func (c *cancelOnSecondCheck) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *cancelOnSecondCheck) Done() <-chan struct{} {
	c.checks++
	if c.checks > 1 {
		return c.closed
	}
	return c.open
}
func (c *cancelOnSecondCheck) Err() error    { return context.Canceled }
func (c *cancelOnSecondCheck) Value(any) any { return nil }

func loadTestConfig(t *testing.T, cfgName string) *config.Config {
	t.Helper()
	cfg, err := config.LoadFile(filepath.Join(configPath, cfgName+".toml"))
	require.NoError(t, err)
	return cfg
}

func newDefaultTestDetector(t *testing.T) *Detector {
	t.Helper()
	cfg, err := config.Default()
	require.NoError(t, err)
	return mustNewDetector(t, cfg)
}

func mustNewDetector(t *testing.T, cfg *config.Config, options ...Option) *Detector {
	t.Helper()
	detector, err := NewDetector(cfg, options...)
	require.NoError(t, err)
	return detector
}

func testConfig() *config.Config {
	return &config.Config{Rules: []config.Rule{{
		RuleID: "test-secret",
		Regex:  regexp.MustCompile(`secret-[a-z]+`),
	}}}
}

func TestDetectorLoggerIsOptIn(t *testing.T) {
	cfg := &config.Config{
		Filter: `missingFunction()`,
		Rules: []config.Rule{{
			RuleID: "test-secret",
			Regex:  regexp.MustCompile(`secret-[a-z]+`),
		}},
	}

	silent := mustNewDetector(t, cfg)
	assert.Equal(t, slog.DiscardHandler, silent.logger.Handler())

	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	detector := mustNewDetector(t, cfg, WithLogger(logger))
	require.Len(t, detector.DetectString("secret-alpha"), 1)
	assert.Contains(t, output.String(), "global filter compile error")
}

func TestDiscardLoggerDoesNotAllocatePerRule(t *testing.T) {
	detector := &Detector{logger: discardLogger}
	fragment := sources.Fragment{Raw: "ordinary input"}
	rule := config.Rule{RuleID: "test-secret", SkipReport: true}

	var findings []report.Finding
	allocations := testing.AllocsPerRun(1_000, func() {
		findings = detector.detectFragmentWithRule(nil, fragment, fragment.Raw, rule, nil, nil)
	})
	runtime.KeepAlive(findings)
	assert.Zero(t, allocations)
}

func TestDetectorScanIsReusableWithValidation(t *testing.T) {
	cfg := testConfig()
	cfg.Rules[0].ValidateExpr = `{"result": "valid"}`
	detector, err := NewDetector(cfg, WithValidation(ValidationOptions{
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

	detector, err := NewDetector(cfg)
	require.NoError(t, err)
	assert.False(t, detector.ValidationEnabled())

	detector, err = NewDetector(cfg, WithValidation(ValidationOptions{}))
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

	detector, err := NewDetector(cfg)
	require.NoError(t, err)
	assert.False(t, detector.ValidationEnabled())
	assert.False(t, detector.AnalysisEnabled())

	detector, err = NewDetector(cfg, WithValidation(ProviderOptions{}))
	require.NoError(t, err)
	assert.True(t, detector.ValidationEnabled())
	assert.False(t, detector.AnalysisEnabled())

	detector, err = NewDetector(cfg, WithAnalysis(ProviderOptions{Workers: 1}))
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
	detector, err := NewDetector(cfg)
	require.NoError(t, err)

	skip := detector.SkipFunc()
	require.NotNil(t, skip)
	assert.True(t, skip(map[string]string{sources.AttrPath: "ignored.txt"}))
	assert.False(t, skip(map[string]string{sources.AttrPath: "kept.txt"}))
}

func TestDetectorScanReturnsHandlerAndSourceErrors(t *testing.T) {
	detector, err := NewDetector(testConfig())
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

	_, err := NewDetector(cfg)
	require.NoError(t, err, "expressions remain lazy by default")

	_, err = NewDetector(cfg, WithPrecompile())
	require.ErrorContains(t, err, "compiling global filter")

	cfg = testConfig()
	cfg.Rules[0].ValidateExpr = `missingFunction()`
	_, err = NewDetector(cfg, WithPrecompile())
	require.ErrorContains(t, err, "validation")
}

func TestNewDetectorValidatesOptions(t *testing.T) {
	_, err := NewDetector(nil)
	assert.Error(t, err)

	_, err = NewDetector(testConfig(), WithJobs(-1))
	assert.ErrorContains(t, err, "jobs")

	_, err = NewDetector(testConfig(), WithMatchContext("bad"))
	assert.ErrorContains(t, err, "match context")

	_, err = NewDetector(testConfig(), WithLogger(nil))
	assert.NoError(t, err)

	_, err = NewDetector(testConfig(), WithValidation(ValidationOptions{
		Statuses: []report.ValidationStatus{"surprising"},
	}))
	assert.ErrorContains(t, err, "invalid validation status")
}

func collectSourceFindings(ctx context.Context, detector *Detector, source sources.Source) ([]report.Finding, error) {
	var (
		findings []report.Finding
		scanErr  error
	)
	for result := range detector.Run(ctx, source) {
		if result.Err != nil {
			scanErr = errors.Join(scanErr, result.Err)
			continue
		}
		findings = append(findings, result.Finding)
	}
	return findings, scanErr
}

func TestRunStreamsFindings(t *testing.T) {
	detector := mustNewDetector(t, loadTestConfig(t, "simple"))
	const content = "ghp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	source := &sources.Reader{
		Content: strings.NewReader(content),
	}

	var findings []report.Finding
	for result := range detector.Run(t.Context(), source) {
		require.NoError(t, result.Err)
		findings = append(findings, result.Finding)
	}

	require.Len(t, findings, 1)
	assert.Empty(t, findings[0].Attr(sources.AttrResource))
	assert.Empty(t, findings[0].Attr(sources.AttrPath))
	assert.Equal(t, report.Location{
		StartLine:   1,
		EndLine:     1,
		StartColumn: 1,
		EndColumn:   len(content),
	}, findings[0].Location)
}

func TestRunWithMultipleJobs(t *testing.T) {
	const fragmentCount = 100

	detector := mustNewDetector(t, loadTestConfig(t, "simple"), WithJobs(4))

	findings, err := collectSourceFindings(t.Context(), detector, repeatedFragmentSource{count: fragmentCount})
	require.NoError(t, err)
	require.Len(t, findings, fragmentCount)
}

func TestRunStopsSourceWhenConsumerStops(t *testing.T) {
	detector := mustNewDetector(t, loadTestConfig(t, "simple"), WithJobs(2))
	source := cancelAwareSource{stopped: make(chan struct{})}

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	for result := range detector.Run(ctx, source) {
		require.NoError(t, result.Err)
		break
	}

	select {
	case <-source.stopped:
	default:
		t.Fatal("source was still running after detector iteration stopped")
	}
}

func TestRunCancellationDoesNotEmitErrors(t *testing.T) {
	detector := mustNewDetector(t, loadTestConfig(t, "simple"), WithJobs(4))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	found := false
	for result := range detector.Run(ctx, repeatedFragmentSource{count: 1000}) {
		require.NoError(t, result.Err)
		if !found {
			found = true
			cancel()
		}
	}
	require.True(t, found)
}

func TestPathOnlyRuleRunsOnFirstFileFragment(t *testing.T) {
	rule := config.Rule{
		RuleID: "path-only",
		Path:   regexp.MustCompile(`\.p12$`),
	}
	cfg := &config.Config{
		Rules: []config.Rule{rule},
	}
	timingCollector := ruletiming.NewCollector()
	detector := mustNewDetector(t, cfg)
	source := &sources.File{
		Content: strings.NewReader("aa\n\nbb\n\n"),
		Path:    "bundle.p12",
		Buffer:  make([]byte, 4),
	}

	var findings []report.Finding
	for result := range detector.Run(ruletiming.WithCollector(t.Context(), timingCollector), source) {
		require.NoError(t, result.Err)
		findings = append(findings, result.Finding)
	}

	require.Len(t, findings, 1)
	timings := timingCollector.Snapshot()
	require.Len(t, timings, 1)
	require.Equal(t, uint64(1), timings[0].Hits)
}

func TestCandidateBitmap(t *testing.T) {
	rules := []config.Rule{
		{RuleID: "high", Specificity: 30, Keywords: []string{"shared", "alias"}, Regex: regexp.MustCompile(`HIGHSECRET`)},
		{RuleID: "low", Specificity: 20, Keywords: []string{"shared"}, Regex: regexp.MustCompile(`LOWSECRET`)},
		{RuleID: "cancel", Specificity: 10, Keywords: []string{"cancel"}, Regex: regexp.MustCompile(`ALWAYSSECRET`)},
		{RuleID: "always", Regex: regexp.MustCompile(`ALWAYSSECRET`)},
	}
	cfg := &config.Config{
		Rules: rules,
	}
	d := mustNewDetector(t, cfg)
	require.Empty(t, d.DetectString("stale HIGHSECRET"))

	// Cancellation after candidates are marked must not leak them into the next scan.
	require.Empty(t, d.detectFragment(newCancelOnSecondCheck(), sources.Fragment{Raw: "cancel ALWAYSSECRET"}))
	require.Equal(t, []string{"always"}, findingRuleIDs(d.DetectString("ALWAYSSECRET")))

	// One keyword selects multiple rules, multiple keywords select one rule,
	// rules without keywords always run, and specificity order is retained.
	require.Equal(t, []string{"high", "low", "always"}, findingRuleIDs(d.DetectString("shared HIGHSECRET LOWSECRET ALWAYSSECRET")))
	require.Equal(t, []string{"high", "always"}, findingRuleIDs(d.DetectString("alias HIGHSECRET ALWAYSSECRET")))
}

func TestNewDetectorSnapshotsConfigWithoutMutatingIt(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{RuleID: "low", Specificity: 10, Keywords: []string{"MiXeD"}, Regex: regexp.MustCompile(`LOWSECRET`)},
		{RuleID: "high", Specificity: 20, Keywords: []string{"MiXeD"}, Regex: regexp.MustCompile(`HIGHSECRET`)},
	}}

	d := mustNewDetector(t, cfg)
	require.Equal(t, []string{"low", "high"}, []string{cfg.Rules[0].RuleID, cfg.Rules[1].RuleID})
	require.Equal(t, "MiXeD", cfg.Rules[0].Keywords[0])
	require.Equal(t, []string{"high", "low"}, []string{d.rulesBySpecificity[0].RuleID, d.rulesBySpecificity[1].RuleID})

	// Detector behavior is isolated from later changes to the caller's config.
	cfg.Rules[0].Keywords[0] = "changed"
	cfg.Rules[0].Regex = regexp.MustCompile(`CHANGED`)
	cfg.Rules[1] = config.Rule{RuleID: "replacement", Keywords: []string{"changed"}, Regex: regexp.MustCompile(`CHANGED`)}
	cfg.Filter = "true"

	require.Equal(t, []string{"high", "low"}, findingRuleIDs(d.DetectString("mixed HIGHSECRET LOWSECRET")))
}

func findingRuleIDs(findings []report.Finding) []string {
	ids := make([]string, len(findings))
	for i := range findings {
		ids[i] = findings[i].RuleID
	}
	return ids
}

const encodedTestValues = `
# Decoded
-----BEGIN PRIVATE KEY-----
135f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb
u+QDkg0spw==
-----END PRIVATE KEY-----

# Encoded
private_key: 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCjQzNWYvYlJVQkhyYkhxTFkveFMzSTdPdGgrOHJnRyswdEJ3Zk1jYmswNVNneHE2UVV6U1lJUUFvcCtXdnNUd2syc1IrQzM4ZzBNbmIKdStRRGtnMHNwdz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K'

# Double Encoded: b64 encoded aws config inside a jwt
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiY29uZmlnIjoiVzJSbFptRjFiSFJkQ25KbFoybHZiaUE5SUhWekxXVmhjM1F0TWdwaGQzTmZZV05qWlhOelgydGxlVjlwWkNBOUlFRlRTVUZKVDFOR1QwUk9UamRNV0UweE1FcEpDbUYzYzE5elpXTnlaWFJmWVdOalpYTnpYMnRsZVNBOUlIZEtZV3h5V0ZWMGJrWkZUVWt2U3pkTlJFVk9SeTlpVUhoU1ptbERXVVZHVlVORWJFVllNVUVLIiwiaWF0IjoxNTE2MjM5MDIyfQ.8gxviXEOuIBQk2LvTYHSf-wXVhnEKC3h4yM5nlOF4zA

# A small secret at the end to make sure that as the other ones above shrink
# when decoded, the positions are taken into consideration for overlaps
c21hbGwtc2VjcmV0

# This tests how it handles when the match bounds go outside the decoded value
secret=ZGVjb2RlZC1zZWNyZXQtdmFsdWUwMA==
# The above encoded again
c2VjcmV0PVpHVmpiMlJsWkMxelpXTnlaWFF0ZG1Gc2RXVT0=

# Confirm you can ignore on the decoded value
password="bFJxQkstejVrZjQtcGxlYXNlLWlnbm9yZS1tZS1YLVhJSk0yUGRkdw=="

# This tests that it can do hex encoded data
secret=6465636F6465642D7365637265742D76616C756576484558

# This tests that it can do percent encoded data
## partial encoded data
secret=decoded-%73%65%63%72%65%74-valuev2
## scattered encoded
secret=%64%65coded-%73%65%63%72%65%74-valuev3

# Test multi levels of encoding where the source is a partal encoding
# it is important that the bounds of the predecessors are properly
# considered
## single percent encoding in the middle of multi layer b64
c2VjcmV0PVpHVmpiMl%4AsWkMxelpXTnlaWFF0ZG1Gc2RXVjJOQT09
## single percent encoding at the beginning of hex
secret%3d6465636F6465642D7365637265742D76616C75657635
## multiple percent encodings in a single layer base64
secret=ZGVjb2%52lZC1zZWNyZXQtdm%46sdWV4ODY=  # ends in x86
## base64 encoded partially percent encoded value
secret=ZGVjb2RlZC0lNzMlNjUlNjMlNzIlNjUlNzQtdmFsdWU=
## one of the lines above that went through... a lot
## and there's surrounding text around it
Look at this value: %4EjMzMjU2NkE2MzZENTYzMDUwNTY3MDQ4%4eTY2RDcwNjk0RDY5NTUzMTRENkQ3ODYx%25%34%65TE3QTQ2MzY1NzZDNjQ0RjY1NTY3MDU5NTU1ODUyNkI2MjUzNTUzMDRFNkU0RTZCNTYzMTU1MzkwQQ== # isn't it crazy?
## Multi percent encode two random characters close to the bounds of the base64
## encoded data to make sure that the bounds are still correctly calculated
secret=ZG%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%36%25%33%31%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%33%25%33%322RlZC1zZWNyZXQtd%25%36%64%25%34%36%25%37%33dWU=
## The similar to the above but also touching the edge of the base64
secret=%25%35%61%25%34%37%25%35%36jb2RlZC1zZWNyZXQtdmFsdWU%25%32%35%25%33%33%25%36%34
## The similar to the above but also touching and overlapping the base64
secret%3D%25%35%61%25%34%37%25%35%36jb2RlZC1zZWNyZXQtdmFsdWU%25%32%35%25%33%33%25%36%34
`

var multili = `
username = "admin"



			password = "secret123"
`

func compare(t *testing.T, got, want []report.Finding) {
	t.Helper()
	got = stripFindingAttributes(append([]report.Finding(nil), got...))
	want = stripFindingAttributes(append([]report.Finding(nil), want...))
	if diff := cmp.Diff(want, got,
		cmpopts.SortSlices(func(a, b report.Finding) bool {
			if a.Attr(sources.AttrPath) != b.Attr(sources.AttrPath) {
				return a.Attr(sources.AttrPath) < b.Attr(sources.AttrPath)
			}
			if a.Location.StartLine != b.Location.StartLine {
				return a.Location.StartLine < b.Location.StartLine
			}
			if a.Location.StartColumn != b.Location.StartColumn {
				return a.Location.StartColumn < b.Location.StartColumn
			}
			if a.Location.EndLine != b.Location.EndLine {
				return a.Location.EndLine < b.Location.EndLine
			}
			if a.Location.EndColumn != b.Location.EndColumn {
				return a.Location.EndColumn < b.Location.EndColumn
			}
			if a.RuleID != b.RuleID {
				return a.RuleID < b.RuleID
			}
			if a.Line != b.Line {
				return a.Line < b.Line
			}
			if a.Secret != b.Secret {
				return a.Secret < b.Secret
			}
			if a.Match != b.Match {
				return a.Match < b.Match
			}
			return strings.Join(a.Tags, "\x00") < strings.Join(b.Tags, "\x00")
		}),
		cmpopts.IgnoreFields(report.Finding{},
			"Attributes", "ComponentSets", "RuleSpecificity"),
		cmpopts.IgnoreFields(report.ComponentFinding{}, "RuleSpecificity"),
		cmpopts.IgnoreUnexported(report.Finding{}),
		cmpopts.EquateApprox(0.0001, 0), // For floating point Entropy comparison
	); diff != "" {
		t.Errorf("findings mismatch (-want +got):\n%s", diff)
	}
}

// stripFindingAttributes clears Attributes from findings for tests that use
// assert.ElementsMatch against expected findings with nil Attributes.
func stripFindingAttributes(findings []report.Finding) []report.Finding {
	for i := range findings {
		findings[i].Attributes = nil
		findings[i].RuleSpecificity = 0
		for si := range findings[i].ComponentSets {
			for ci := range findings[i].ComponentSets[si].Components {
				findings[i].ComponentSets[si].Components[ci].RuleSpecificity = 0
			}
		}
		findings[i].SetExprContext("")
	}
	return findings
}

func TestRequiredAndOptionalComponents(t *testing.T) {
	cfg, err := config.ParseTOMLString(`
[[rules]]
id = "primary"
regex = '''primary=([a-z]+)'''
components = [
  { id = "required-component" },
  { id = "optional-component", optional = true },
]

[[rules]]
id = "required-component"
regex = '''required=([a-z]+)'''
skipReport = true

[[rules]]
id = "optional-component"
regex = '''optional=([a-z]+)'''
skipReport = true
`, "")
	require.NoError(t, err)
	detector := mustNewDetector(t, cfg)

	t.Run("required component gates finding", func(t *testing.T) {
		assert.Empty(t, detector.DetectString("primary=secret\noptional=session"))
	})

	t.Run("absent optional component is omitted", func(t *testing.T) {
		findings := detector.DetectString("primary=secret\nrequired=account")
		require.Len(t, findings, 1)
		require.Len(t, findings[0].ComponentSets, 1)
		require.Len(t, findings[0].ComponentSets[0].Components, 1)
		component := findings[0].ComponentSets[0].Components[0]
		assert.Equal(t, "required-component", component.RuleID)
		assert.False(t, component.Optional)
	})

	t.Run("present optional component joins combinations", func(t *testing.T) {
		findings := detector.DetectString("primary=secret\nrequired=account\noptional=first\noptional=second")
		require.Len(t, findings, 1)
		require.Len(t, findings[0].ComponentSets, 2)
		for _, set := range findings[0].ComponentSets {
			require.Len(t, set.Components, 2)
			assert.False(t, set.Components[0].Optional)
			assert.True(t, set.Components[1].Optional)
		}
	})
}

func TestOptionalOnlyComponents(t *testing.T) {
	cfg, err := config.ParseTOMLString(`
[[rules]]
id = "primary"
regex = '''primary=([a-z]+)'''
specificity = 20
components = [{ id = "optional-component", optional = true }]

[[rules]]
id = "optional-component"
regex = '''optional=([a-z]+)'''
specificity = 100
skipReport = true
`, "")
	require.NoError(t, err)
	detector := mustNewDetector(t, cfg)

	findings := detector.DetectString("primary=secret")
	require.Len(t, findings, 1)
	assert.Empty(t, findings[0].ComponentSets)

	findings = detector.DetectString("primary=secret\noptional=session")
	require.Len(t, findings, 1)
	require.Len(t, findings[0].ComponentSets, 1)
	require.Len(t, findings[0].ComponentSets[0].Components, 1)
	assert.True(t, findings[0].ComponentSets[0].Components[0].Optional)

	findings = detector.DetectString("primary=shared optional=shared")
	require.Len(t, findings, 1, "a primary must not be suppressed by its own same-line, same-value component")
	require.Len(t, findings[0].ComponentSets, 1)
	assert.Equal(t, "shared", findings[0].ComponentSets[0].Components[0].Secret)
}

func TestGenericPasswordConfidenceAndContext(t *testing.T) {
	detector := newDefaultTestDetector(t)

	genericPasswordFindings := func(raw string, path ...string) []report.Finding {
		t.Helper()
		detected := detector.DetectString(raw)
		if len(path) > 0 {
			detected = detector.detectFragment(context.Background(), sources.Fragment{
				Raw:        raw,
				Attributes: map[string]string{sources.AttrPath: path[0]},
			})

		}
		var findings []report.Finding
		for _, finding := range detected {
			if finding.RuleID == "generic-password" {
				findings = append(findings, finding)
			}
		}
		return findings
	}

	for name, raw := range map[string]string{
		"weak standalone password":          "password: hunter2",
		"uppercase weak password":           `password = "PASSWORD"`,
		"random standalone password":        "password: Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB",
		"password containing username text": `password: "username: alice"`,
		"password containing a URI":         `password: "postgres://db.internal/app"`,
		"password containing its key name":  `password: "MyPassword123!"`,
		"password containing login syntax":  `password = "please login(foo"`,
		"password containing assignment":    `password = "safe password = process.env.PASSWORD"`,
		"password ending in parenthesis":    `password = "hunter2)"`,
		"password resembling Rake syntax":   `password = "foo:[bar]"`,
	} {
		t.Run(name, func(t *testing.T) {
			findings := genericPasswordFindings(raw)
			require.Len(t, findings, 1)
			assert.Equal(t, "low", findings[0].Confidence)
		})
	}

	for name, raw := range map[string]string{
		"hash comment":          `password = "hunter2"  # development password`,
		"slash comment":         `password = "hunter2" // TODO: move to vault`,
		"block comment":         `password = "hunter2" /* TODO: move to vault`,
		"SQL comment":           `password = "hunter2" -- local database`,
		"unquoted with comment": `password = hunter2 # development password`,
	} {
		t.Run(name, func(t *testing.T) {
			findings := genericPasswordFindings(raw)
			require.Len(t, findings, 1)
			assert.Equal(t, "hunter2", findings[0].Secret)
			assert.Equal(t, "low", findings[0].Confidence)
		})
	}

	unquotedHash := genericPasswordFindings(`password = hunter2#prod`)
	require.Len(t, unquotedHash, 1)
	assert.Equal(t, "hunter2#prod", unquotedHash[0].Secret)

	assert.Empty(t, genericPasswordFindings("username: alice\npassword: your_password"))
	assert.Empty(t, genericPasswordFindings(`password = "${DB_PASSWORD}"`))
	assert.Empty(t, genericPasswordFindings(`password = getPassword()`))
	assert.Empty(t, genericPasswordFindings(`password = "[REDACTED]"`))
	assert.Empty(t, genericPasswordFindings("database.host = db.internal\ndatabase_pw = undefined"))

	for name, tc := range map[string]struct {
		path string
		raw  string
	}{
		"encrypted password field with opaque literal": {
			path: "services/settings.json",
			raw:  `"encryptedPassword": "MDoEEPgAAAAAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcEC",`,
		},
		"encrypted password field with plaintext literal": {
			path: "config/database.yml",
			raw:  `encrypted_password: "hunter2"`,
		},
		"encrypted password field with dictionary cipher name": {
			path: "config/database.yml",
			raw:  `encrypted_password: "Blowfish"`,
		},
		"vault password field with plaintext literal": {
			path: "config/vault.yml",
			raw:  `vault_password: "hunter2"`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			findings := genericPasswordFindings(tc.raw, tc.path)
			require.Len(t, findings, 1)
			assert.Equal(t, "low", findings[0].Confidence)
		})
	}

	for name, tc := range map[string]struct {
		path string
		raw  string
	}{
		"shell command substitution": {
			path: "config/setup.sh",
			raw:  `keystore_password=$(curl --silent https://example.invalid/password)`,
		},
		"Ruby interpolation": {
			path: "config/credentials.rb",
			raw:  `password: "pw_#{SecureRandom.hex(4)}"`,
		},
		"Python mapping interpolation": {
			path: "app/database.py",
			raw:  `query = "ALTER USER %(user)s WITH PASSWORD %(password)s"`,
		},
		"Rake expression": {
			path: "lib/tasks/accounts.rake",
			raw:  `password: password).relay(STDIN.read),`,
		},
		"CLI option": {
			path: "lib/commands.rb",
			raw:  `password: "--password"`,
		},
		"Rake task arguments": {
			path: "lib/tasks/passwords.rake",
			raw:  `gitlab:password:check_hashes:[true]`,
		},
		"nested unquoted assignment": {
			path: "Documentation/admin-guide/kernel-parameters.txt",
			raw:  `password=mypassword.domain=mydom`,
		},
		"Django PBKDF2 verifier": {
			path: "fixtures/users.json",
			raw:  `"password": "pbkdf2_sha256$30000$salt$H9BEzMlGhw=="`,
		},
		"LDAP verifier": {
			path: "config/ldap.yml",
			raw:  `password: "{SSHA}bW9ja2VkLXNzaGEtZGlnZXN0"`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, genericPasswordFindings(tc.raw, tc.path))
		})
	}

	rubyVariables := `def basic_auth
  { username: username, password: password }
end`
	assert.Empty(t, genericPasswordFindings(rubyVariables, "auth.rb"))

	for name, tc := range map[string]struct {
		path string
		raw  string
	}{
		"Ruby method chain": {
			path: "app/helpers/profiles_helper.rb",
			raw:  `confirm_with_password: current_user.confirm_deletion_with_password?.to_s,`,
		},
		"Go field selector": {
			path: "internal/redis/redis_test.go",
			raw:  `SentinelPassword: tc.inputSentinelPassword,`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, genericPasswordFindings(tc.raw, tc.path))
		})
	}

	rubyLiteralPassword := genericPasswordFindings(
		`credentials = { username: username, password: "hunter2" }`,
		"auth.rb",
	)
	require.Len(t, rubyLiteralPassword, 1)
	assert.Equal(t, "hunter2", rubyLiteralPassword[0].Secret)
	assert.Equal(t, "medium", rubyLiteralPassword[0].Confidence)
	assert.Empty(t, rubyLiteralPassword[0].ComponentSets, "a Ruby variable must not be attached as a literal username")

	quotedExpressionText := genericPasswordFindings(
		`credentials = { password: "current_user.confirm_deletion_with_password?.to_s" }`,
		"auth.rb",
	)
	require.Len(t, quotedExpressionText, 1)
	assert.Equal(t, "current_user.confirm_deletion_with_password?.to_s", quotedExpressionText[0].Secret)

	rubyLiterals := genericPasswordFindings(
		`credentials = { username: "alice", password: "hunter2" }`,
		"auth.rb",
	)
	require.Len(t, rubyLiterals, 1)
	require.Len(t, rubyLiterals[0].ComponentSets, 1)
	assert.Equal(t, "alice", rubyLiterals[0].ComponentSets[0].Components[0].Secret)

	anchoredUsernameFilter := genericPasswordFindings(
		`credentials = { username: "safe username = null, suffix", password: "hunter2" }`,
		"auth.rb",
	)
	require.Len(t, anchoredUsernameFilter, 1)
	require.Len(t, anchoredUsernameFilter[0].ComponentSets, 1)
	assert.Equal(t, "safe username = null, suffix", anchoredUsernameFilter[0].ComponentSets[0].Components[0].Secret)

	camelCaseClient := genericPasswordFindings(
		`credentials = { clientId: "service-client", password: "hunter2" }`,
		"auth.js",
	)
	require.Len(t, camelCaseClient, 1)
	assert.Equal(t, "medium", camelCaseClient[0].Confidence)
	require.Len(t, camelCaseClient[0].ComponentSets, 1)
	assert.Equal(t, "service-client", camelCaseClient[0].ComponentSets[0].Components[0].Secret)

	yamlScalars := genericPasswordFindings("credentials:\n  username: alice\n  password: hunter2", "config.yml")
	require.Len(t, yamlScalars, 1)
	require.Len(t, yamlScalars[0].ComponentSets, 1)
	assert.Equal(t, "alice", yamlScalars[0].ComponentSets[0].Components[0].Secret)

	usernameOnly := genericPasswordFindings("USERNAME=alice@example.com\nPASSWORD=hunter2")
	require.Len(t, usernameOnly, 1)
	assert.Equal(t, "low", usernameOnly[0].Confidence)
	require.Len(t, usernameOnly[0].ComponentSets, 1)
	assert.Equal(t, "generic-username", usernameOnly[0].ComponentSets[0].Components[0].RuleID)

	paired := genericPasswordFindings("credentials: {\nusername: alice\npassword: hunter2\n}")
	require.Len(t, paired, 1)
	assert.Equal(t, "medium", paired[0].Confidence)
	require.Len(t, paired[0].ComponentSets, 1)
	require.Len(t, paired[0].ComponentSets[0].Components, 1)
	assert.Equal(t, "generic-username", paired[0].ComponentSets[0].Components[0].RuleID)
	assert.Equal(t, "alice", paired[0].ComponentSets[0].Components[0].Secret)

	for name, tc := range map[string]struct {
		path string
		raw  string
	}{
		"commented credential": {
			path: "config/credentials.rb",
			raw:  `# credentials = { username: "alice", password: "hunter2" }`,
		},
		"replace-me value": {
			path: "config/database.yml",
			raw:  "credentials: {\nusername: alice\npassword: replace_me\n}",
		},
		"symbolic password name": {
			path: "config/database.yml",
			raw:  "credentials: {\nusername: alice\npassword: PGPASSWORD\n}",
		},
		"example value": {
			path: "config/database.yml",
			raw:  "credentials: {\nusername: alice\npassword: example\n}",
		},
		"numbered example value": {
			path: "config/database.yml",
			raw:  "credentials: {\nusername: alice\npassword: example123!\n}",
		},
		"example password value": {
			path: "config/database.yml",
			raw:  "credentials: {\nusername: alice\npassword: example_password\n}",
		},
		"reversed example value": {
			path: "config/database.yml",
			raw:  "credentials: {\nusername: alice\npassword: PasswordExample!\n}",
		},
	} {
		t.Run(name, func(t *testing.T) {
			findings := genericPasswordFindings(tc.raw, tc.path)
			require.Len(t, findings, 1)
			assert.Equal(t, "low", findings[0].Confidence)
		})
	}

	for name, tc := range map[string]struct {
		path string
		raw  string
	}{
		"test directory": {
			path: "test/fixtures/database.yml",
			raw:  "credentials: {\nusername: alice\npassword: hunter2\n}",
		},
		"example filename": {
			path: "config/database.example.yml",
			raw:  "credentials: {\nusername: alice\npassword: hunter2\n}",
		},
		"README": {
			path: "README.md",
			raw:  "credentials: {\nusername: alice\npassword: hunter2\n}",
		},
		"direct auth in spec": {
			path: "src/authentication.spec.js",
			raw:  `smtp.login(username, "hunter2")`,
		},
		"human password phrase": {
			path: "config/database.yml.example",
			raw:  "credentials: {\nusername: git\npassword: \"secure password\"\n}",
		},
		"test credential object": {
			path: "spec/models/application_setting_spec.rb",
			raw:  `{ protocol: "http", user: "admin", password: "p@ssword", host: "localhost" }`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			findings := genericPasswordFindings(tc.raw, tc.path)
			require.Len(t, findings, 1)
			assert.Equal(t, "medium", findings[0].Confidence)
		})
	}

	productionCredential := genericPasswordFindings(
		"database_host: db.internal\ncredentials: {\nusername: alice\npassword: hunter2\n}",
		"config/database.yml",
	)
	require.Len(t, productionCredential, 1)
	assert.Equal(t, "medium", productionCredential[0].Confidence)

	prefixedEnvironmentCredential := genericPasswordFindings(
		"POSTGRES_DB: app\nPOSTGRES_USER: alice\nPOSTGRES_PASSWORD: hunter2",
		".github/workflows/integration.yml",
	)
	require.Len(t, prefixedEnvironmentCredential, 1)
	assert.Equal(t, "medium", prefixedEnvironmentCredential[0].Confidence)

	weakDefaultCredential := genericPasswordFindings(
		"credentials: {\nusername: alice\npassword: changeme\n}",
		"config/database.yml",
	)
	require.Len(t, weakDefaultCredential, 1)
	assert.Equal(t, "medium", weakDefaultCredential[0].Confidence)

	rakeVariables := genericPasswordFindings(
		`credentials = { username: username, password: "hunter2" }`,
		"lib/tasks/authentication.rake",
	)
	require.Len(t, rakeVariables, 1)
	assert.Equal(t, "medium", rakeVariables[0].Confidence)
	assert.Empty(t, rakeVariables[0].ComponentSets, "a Rake variable must not be attached as a literal username")

	promoted := genericPasswordFindings("credentials: {\nusername: alice@example.com\npassword: \"#exFfrbtEpo&RaTkZ#%*zFgS\"\n}")
	require.Len(t, promoted, 1)
	assert.Equal(t, "medium", promoted[0].Confidence)

	authOnly := genericPasswordFindings("credentials: {\npassword: \"#exFfrbtEpo&RaTkZ#%*zFgS\"\n}")
	require.Len(t, authOnly, 1)
	assert.Equal(t, "low", authOnly[0].Confidence)

	strongUsernameOnly := genericPasswordFindings("username: alice@example.com\npassword: \"#exFfrbtEpo&RaTkZ#%*zFgS\"")
	require.Len(t, strongUsernameOnly, 1)
	assert.Equal(t, "low", strongUsernameOnly[0].Confidence)

	dynamicUsername := genericPasswordFindings("credentials: {\nusername: process.env.USERNAME\npassword: hunter2\n}")
	require.Len(t, dynamicUsername, 1)
	assert.Equal(t, "medium", dynamicUsername[0].Confidence)
	assert.Empty(t, dynamicUsername[0].ComponentSets, "a dynamic username is auth context but not an attachable component")

	for name, raw := range map[string]string{
		"underscore with database asset": "database.host = db.internal\ndatabase_pw = J8svR4qL7nT2xM6zK9",
		"hyphen in connection call":      "service.connect(\n  service-pw: Qv7D0LXCM3EIMbgJpUNnkRtOfOueHznB\n)",
		"dot with dsn":                   "dsn: postgres://db.internal/app\nclient.pw = m4FqK8zR2tV6xN9pC7",
	} {
		t.Run(name, func(t *testing.T) {
			findings := genericPasswordFindings(raw)
			require.Len(t, findings, 1)
			assert.Equal(t, "low", findings[0].Confidence)
			assert.Empty(t, findings[0].ComponentSets)
		})
	}

	weakAliasPair := genericPasswordFindings("credentials: {\nusername: alice\ndatabase_pw: hunter2\n}")
	require.Len(t, weakAliasPair, 1)
	assert.Equal(t, "medium", weakAliasPair[0].Confidence)
	require.Len(t, weakAliasPair[0].ComponentSets, 1)

	insideWindow := "login()\n" + strings.Repeat("context line\n", 4) + "username: alice\npassword: hunter2"
	insideWindowFindings := genericPasswordFindings(insideWindow)
	require.Len(t, insideWindowFindings, 1)
	assert.Equal(t, "medium", insideWindowFindings[0].Confidence)

	outsideWindow := "login()\n" + strings.Repeat("context line\n", 5) + "username: alice\npassword: hunter2"
	outsideWindowFindings := genericPasswordFindings(outsideWindow)
	require.Len(t, outsideWindowFindings, 1)
	assert.Equal(t, "low", outsideWindowFindings[0].Confidence)

	for name, tc := range map[string]struct {
		raw    string
		secret string
	}{
		"login": {
			raw:    `smtp.login(username, "hunter2")`,
			secret: "hunter2",
		},
		"four character login password": {
			raw:    `login(user, "root")`,
			secret: "root",
		},
		"uppercase weak login password": {
			raw:    `login(user, "PASSWD")`,
			secret: "PASSWD",
		},
		"authenticate": {
			raw:    `client.authenticate(user, "password1")`,
			secret: "password1",
		},
		"authenticate account selector": {
			raw:    `client.authenticate(account.id, "root")`,
			secret: "root",
		},
		"log in alias": {
			raw:    `service.log_in(account, 'correct horse battery staple')`,
			secret: "correct horse battery staple",
		},
	} {
		t.Run(name, func(t *testing.T) {
			findings := genericPasswordFindings(tc.raw)
			require.Len(t, findings, 1)
			assert.Equal(t, tc.secret, findings[0].Secret)
			assert.Equal(t, "medium", findings[0].Confidence)
			assert.Empty(t, findings[0].ComponentSets)
		})
	}

	for name, raw := range map[string]string{
		"request and basic": `authenticate(request, "basic")`,
		"request and oauth": `authenticate(request, "oauth2")`,
	} {
		t.Run(name, func(t *testing.T) {
			findings := genericPasswordFindings(raw)
			require.Len(t, findings, 1)
			assert.Equal(t, "low", findings[0].Confidence)
		})
	}

	assert.Empty(t, genericPasswordFindings(`postgres://user:hunter2@example.com/db`))
	assert.Empty(t, genericPasswordFindings(`ldap.bind(user, "hunter2")`))
	assert.Empty(t, genericPasswordFindings(`log.in(user, "hunter2")`))
	assert.Empty(t, genericPasswordFindings(`log-in(user, "hunter2")`))
}

func TestGenericCredentialURI(t *testing.T) {
	detector := newDefaultTestDetector(t)

	findingsForRule := func(raw, ruleID string, path ...string) []report.Finding {
		t.Helper()
		detected := detector.DetectString(raw)
		if len(path) > 0 {
			detected = detector.detectFragment(context.Background(), sources.Fragment{
				Raw:        raw,
				Attributes: map[string]string{sources.AttrPath: path[0]},
			})

		}
		var findings []report.Finding
		for _, finding := range detected {
			if finding.RuleID == ruleID {
				findings = append(findings, finding)
			}
		}
		return findings
	}

	for name, tc := range map[string]struct {
		raw      string
		secret   string
		scheme   string
		username string
		host     string
	}{
		"PostgreSQL": {
			raw:      `DATABASE_URL="postgresql://alice:hunter2@db.internal/app"`,
			secret:   "hunter2",
			scheme:   "postgresql",
			username: "alice",
			host:     "db.internal",
		},
		"HTTPS basic auth": {
			raw:      `SERVICE_URL="https://alice:s3cr3t@service.internal/api"`,
			secret:   "s3cr3t",
			scheme:   "https",
			username: "alice",
			host:     "service.internal",
		},
		"HTTP percent-encoded password": {
			raw:      `PROXY_URL=http://api-user:p%40ssword@proxy.internal:8080/v1`,
			secret:   "p%40ssword",
			scheme:   "http",
			username: "api-user",
			host:     "proxy.internal",
		},
		"password-only Redis": {
			raw:    `REDIS_URL=redis://:s3cr3t@cache.internal:6379/0`,
			secret: "s3cr3t",
			scheme: "redis",
			host:   "cache.internal",
		},
		"percent-encoded AMQP": {
			raw:      `AMQP_URL='amqps://service:p%40ssword@rabbitmq.internal/vhost'`,
			secret:   "p%40ssword",
			scheme:   "amqps",
			username: "service",
			host:     "rabbitmq.internal",
		},
		"short weak password": {
			raw:      `SSH_URL=ssh://root:root@192.0.2.10:22/`,
			secret:   "root",
			scheme:   "ssh",
			username: "root",
			host:     "192.0.2.10",
		},
		"IPv6 host and fragment": {
			raw:      `MYSQL_URL=mysql://service:p%2Fss@[2001:db8::1]:3306#primary`,
			secret:   "p%2Fss",
			scheme:   "mysql",
			username: "service",
			host:     "[2001:db8::1]",
		},
	} {
		t.Run(name, func(t *testing.T) {
			findings := findingsForRule(tc.raw, "generic-credential-uri")
			require.Len(t, findings, 1)
			finding := findings[0]
			assert.Equal(t, tc.secret, finding.Secret)
			assert.Equal(t, "medium", finding.Confidence)
			assert.Equal(t, tc.scheme, finding.CaptureGroups["scheme"])
			assert.Equal(t, tc.username, finding.CaptureGroups["username"])
			assert.Equal(t, tc.secret, finding.CaptureGroups["password"])
			assert.Equal(t, tc.host, finding.CaptureGroups["host"])
			assert.Contains(t, finding.CaptureGroups["uri"], tc.secret)
		})
	}

	for name, password := range map[string]string{
		"example":          "example",
		"numbered example": "example123!",
		"example password": "example_password",
		"reversed example": "PasswordExample!",
		"encoded example":  "example%5Fpassword",
	} {
		t.Run(name, func(t *testing.T) {
			findings := findingsForRule("postgres://alice:"+password+"@db.internal/app", "generic-credential-uri")
			require.Len(t, findings, 1)
			assert.Equal(t, password, findings[0].Secret)
			assert.Equal(t, "low", findings[0].Confidence)
		})
	}

	for name, raw := range map[string]string{
		"generic username and password": `https://username:password@gitlab.company.com/api`,
		"foo and bar":                   `https://foo:bar@demo.host/api`,
		"numbered test tuple":           `https://test123:test123!@anotherhost/api`,
	} {
		t.Run(name, func(t *testing.T) {
			findings := findingsForRule(raw, "generic-credential-uri")
			require.Len(t, findings, 1)
			assert.Equal(t, "low", findings[0].Confidence)
		})
	}

	for name, raw := range map[string]string{
		"reserved invalid TLD":   `ssh://alice:hunter2@host.invalid/repository`,
		"reserved test TLD":      `https://alice:s3cr3t@service.test/v1`,
		"localhost":              `https://alice:s3cr3t@localhost/v1`,
		"localhost subdomain":    `redis://:s3cr3t@cache.localhost:6379/0`,
		"localhost trailing dot": `redis://:s3cr3t@cache.localhost.:6379/0`,
		"documentation and test": `postgresql://alice:hunter2@example.com,service.test/app`,
	} {
		t.Run(name, func(t *testing.T) {
			findings := findingsForRule(raw, "generic-credential-uri")
			require.Len(t, findings, 1)
			assert.Equal(t, "low", findings[0].Confidence)
		})
	}

	for name, path := range map[string]string{
		"test directory":          `test/integration/client.go`,
		"spec filename":           `app/services/client_spec.rb`,
		"fixture directory":       `config/fixtures/database.yml`,
		"testdata directory":      `internal/client/testdata/config.yml`,
		"example filename":        `config/database.example.yml`,
		"template directory":      `ci/templates/database.yml`,
		"QA directory":            `qa/runtime/config.rb`,
		"documentation directory": `doc-locale/ja-jp/setup.md`,
		"documentation extension": `guides/setup.rst`,
		"readme":                  `config/README.md`,
		"Windows test path":       `test\fixtures\database.yml`,
	} {
		t.Run(name, func(t *testing.T) {
			findings := findingsForRule(
				`postgresql://alice:hunter2@db.internal/app`,
				"generic-credential-uri",
				path,
			)
			require.Len(t, findings, 1)
			assert.Equal(t, "low", findings[0].Confidence)
		})
	}

	productionSource := findingsForRule(
		`postgresql://alice:hunter2@db.internal/app`,
		"generic-credential-uri",
		`config/production.yml`,
	)
	require.Len(t, productionSource, 1)
	assert.Equal(t, "medium", productionSource[0].Confidence)

	// Weak and common default passwords are still credentials when embedded in
	// a URI; their strength must not be confused with detection confidence.
	for _, password := range []string{"changeme", "password", "guest"} {
		findings := findingsForRule("postgres://alice:"+password+"@db.internal/app", "generic-credential-uri")
		require.Len(t, findings, 1)
		assert.Equal(t, "medium", findings[0].Confidence)
	}

	for name, raw := range map[string]string{
		"missing password":             `postgres://alice@db.internal/app`,
		"empty password":               `postgres://alice:@db.internal/app`,
		"braced variable":              `postgres://alice:${DB_PASSWORD}@db.internal/app`,
		"shell variable":               `postgres://alice:$DB_PASSWORD@db.internal/app`,
		"template expressions":         `postgres://{{ db_user }}:{{ db_password }}@db.internal/app`,
		"angle placeholders":           `postgres://<username>:<password>@db.internal/app`,
		"synthetic SSH URI":            `ssh://foo:bar@example.com`,
		"synthetic database URI":       `postgres://username:password@example.org/app`,
		"synthetic FTP URI":            `ftp://foo:bar@test.com/repository`,
		"example.com host":             `https://alice:s3cr3t@example.com/api`,
		"example.com subdomain":        `https://alice:s3cr3t@api.example.com/v1`,
		"example.com underscore host":  `http://user:pass:word@old_configurator.example.com)`,
		"example.net host":             `postgres://alice:hunter2@db.example.net/app`,
		"reserved example TLD":         `redis://:s3cr3t@cache.example/0`,
		"example.com trailing dot":     `https://alice:s3cr3t@example.com./v1`,
		"example.com query":            `https://alice:s3cr3t@example.com?mode=test`,
		"all reserved hosts":           `postgresql://alice:hunter2@example.com,db.example.net/app`,
		"instructional Redis password": `redis://:redis-password-goes-here@gitlab-redis/`,
		"masked Redis password":        `redis://:xxxx@gitlab-redis/`,
		"braced HTTP placeholder":      `http://user:{password}@service.internal/`,
		"replace-me password":          `postgres://alice:replace_me@db.internal/app`,
		"HTTPS URL without userinfo":   `https://example.com/api`,
		"email-like text":              `alice:hunter2@example.com`,
	} {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, findingsForRule(raw, "generic-credential-uri"))
		})
	}

	assert.Empty(t, findingsForRule(
		`http://username:password@example.com,https://test:test@example.org:9200`,
		"generic-credential-uri",
	))

	placeholderShapedInternalURI := findingsForRule(
		`ssh://foo:bar@gitlab.internal/repository`,
		"generic-credential-uri",
	)
	require.Len(t, placeholderShapedInternalURI, 1)
	assert.Equal(t, "low", placeholderShapedInternalURI[0].Confidence)

	nonReservedExamplePrefix := findingsForRule(
		`https://alice:s3cr3t@example.company.internal/v1`,
		"generic-credential-uri",
	)
	require.Len(t, nonReservedExamplePrefix, 1)
	assert.Equal(t, "medium", nonReservedExamplePrefix[0].Confidence)

	nonReservedLocalhostPrefix := findingsForRule(
		`https://alice:s3cr3t@localhost.internal/v1`,
		"generic-credential-uri",
	)
	require.Len(t, nonReservedLocalhostPrefix, 1)
	assert.Equal(t, "medium", nonReservedLocalhostPrefix[0].Confidence)

	for name, raw := range map[string]string{
		"reserved host first":  `postgresql://alice:hunter2@example.com,db.internal/app`,
		"reserved host last":   `postgresql://alice:hunter2@db.internal,example.com/app`,
		"localhost host first": `postgresql://alice:hunter2@localhost,db.internal/app`,
		"test host last":       `postgresql://alice:hunter2@db.internal,service.test/app`,
	} {
		t.Run(name, func(t *testing.T) {
			findings := findingsForRule(raw, "generic-credential-uri")
			require.Len(t, findings, 1)
			assert.Equal(t, "medium", findings[0].Confidence)
		})
	}

	// Provider-specific rules should suppress this generic fallback when they
	// accept the same credential.
	mongodb := detector.DetectString(`MONGO_URL="mongodb://svc-reader:q9V7nB2K4xL8@mongo.internal:27017/app"`)
	var mongodbRules []string
	for _, finding := range mongodb {
		if finding.RuleID == "mongodb-connection-string" || finding.RuleID == "generic-credential-uri" {
			mongodbRules = append(mongodbRules, finding.RuleID)
		}
	}
	assert.Equal(t, []string{"mongodb-connection-string"}, mongodbRules)
}

func TestComponentProximity(t *testing.T) {
	tests := []struct {
		name              string
		raw               string
		fragmentStartLine int
		primary           report.Finding
		component         report.Finding
		within            string
		want              bool
	}{
		{
			name:      "symmetric lines inside",
			primary:   report.Finding{Location: report.Location{StartLine: 10, EndLine: 10, StartColumn: 10, EndColumn: 16}},
			component: report.Finding{Location: report.Location{StartLine: 14, EndLine: 14, StartColumn: 10, EndColumn: 14}},
			within:    "5L",
			want:      true,
		},
		{
			name:      "symmetric lines outside",
			primary:   report.Finding{Location: report.Location{StartLine: 10, EndLine: 10, StartColumn: 10, EndColumn: 16}},
			component: report.Finding{Location: report.Location{StartLine: 15, EndLine: 15, StartColumn: 10, EndColumn: 14}},
			within:    "5L",
			want:      false,
		},
		{
			name:      "directed lines before",
			primary:   report.Finding{Location: report.Location{StartLine: 10, EndLine: 10, StartColumn: 10, EndColumn: 16}},
			component: report.Finding{Location: report.Location{StartLine: 9, EndLine: 9, StartColumn: 10, EndColumn: 14}},
			within:    "-2L",
			want:      true,
		},
		{
			name:      "directed lines reject opposite side",
			primary:   report.Finding{Location: report.Location{StartLine: 10, EndLine: 10, StartColumn: 10, EndColumn: 16}},
			component: report.Finding{Location: report.Location{StartLine: 11, EndLine: 11, StartColumn: 10, EndColumn: 14}},
			within:    "-2L",
			want:      false,
		},
		{
			name:              "character offsets before",
			raw:               "COMP PRIMARY",
			fragmentStartLine: 0,
			primary:           report.Finding{Location: report.Location{StartLine: 0, EndLine: 0, StartColumn: 6, EndColumn: 12}},
			component:         report.Finding{Location: report.Location{StartLine: 0, EndLine: 0, StartColumn: 1, EndColumn: 4}},
			within:            "-5C",
			want:              true,
		},
		{
			name:              "character offsets outside",
			raw:               "COMP PRIMARY",
			fragmentStartLine: 0,
			primary:           report.Finding{Location: report.Location{StartLine: 0, EndLine: 0, StartColumn: 6, EndColumn: 12}},
			component:         report.Finding{Location: report.Location{StartLine: 0, EndLine: 0, StartColumn: 1, EndColumn: 4}},
			within:            "-4C",
			want:              false,
		},
		{
			name:      "mixed line and column window",
			primary:   report.Finding{Location: report.Location{StartLine: 10, EndLine: 10, StartColumn: 10, EndColumn: 16}},
			component: report.Finding{Location: report.Location{StartLine: 9, EndLine: 9, StartColumn: 7, EndColumn: 11}},
			within:    "-2L,-3C",
			want:      true,
		},
		{
			name:      "mixed window rejects column",
			primary:   report.Finding{Location: report.Location{StartLine: 10, EndLine: 10, StartColumn: 10, EndColumn: 16}},
			component: report.Finding{Location: report.Location{StartLine: 9, EndLine: 9, StartColumn: 7, EndColumn: 11}},
			within:    "-2L,-2C",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			window, err := contextwindow.Parse(tt.within)
			require.NoError(t, err)
			assert.Equal(t, tt.want, withinProximity(tt.raw, tt.fragmentStartLine, tt.primary, tt.component, window))
		})
	}
}

func TestDirectionalWithinComponents(t *testing.T) {
	cfg, err := config.ParseTOMLString(`
[[rules]]
id = "primary"
regex = '''primary=([a-z]+)'''
components = [{ id = "optional-component", optional = true, within = "-2L" }]

[[rules]]
id = "optional-component"
regex = '''optional=([a-z]+)'''
skipReport = true
`, "")
	require.NoError(t, err)
	detector := mustNewDetector(t, cfg)

	findings := detector.DetectString("optional=session\nprimary=secret")
	require.Len(t, findings, 1)
	require.Len(t, findings[0].ComponentSets, 1)

	findings = detector.DetectString("primary=secret\noptional=session")
	require.Len(t, findings, 1)
	assert.Empty(t, findings[0].ComponentSets)
}

func TestDetectFilterMatchesContextWindow(t *testing.T) {
	rule := config.Rule{
		RuleID: "near-match",
		Regex:  regexp.MustCompile(`[A-Z0-9]{20}`),
		Filter: `let matchContext = finding["fragment_raw"][max(finding["match_start_idx"] - 50, 0):finding["match_end_idx"]]; filter.matchesAny(matchContext, ["red-herring"])`,
	}
	cfg := &config.Config{
		Rules: []config.Rule{rule},
	}

	d := mustNewDetector(t, cfg)
	findings := d.detectFragment(context.Background(), sources.Fragment{Raw: "red-herring " + strings.Repeat("x", 55) + " ABCDEFGHIJKLMNOPQRST"})

	require.Len(t, findings, 1)
	assert.Equal(t, "ABCDEFGHIJKLMNOPQRST", findings[0].Secret)
}

func TestConfidenceAttributeAndFilter(t *testing.T) {
	low := config.Rule{RuleID: "specific-low", Regex: regexp.MustCompile(`[A-Z0-9]{20}`), Specificity: 1, Confidence: "low"}
	promoted := config.Rule{RuleID: "promoted", Regex: regexp.MustCompile(`[A-Z0-9]{20}`), Confidence: "medium", Filter: `let _ = filter.setConfidence("high"); false`}
	cfg := &config.Config{
		Rules: []config.Rule{low, promoted},
	}

	detector := mustNewDetector(t, cfg, WithMinimumConfidence(ConfidenceHigh))
	findings := detector.DetectString("ABCDEFGHIJKLMNOPQRST")
	require.Len(t, findings, 1)
	require.Equal(t, "promoted", findings[0].RuleID)
	require.Equal(t, "high", findings[0].Confidence)
}

func TestDecodedFilterUsesDecodedMatchContext(t *testing.T) {
	decoded := "provider decoded-secret-ABCDEFGHIJKLMNOPQRST"
	raw := base64.StdEncoding.EncodeToString([]byte(decoded))

	for _, tc := range []struct {
		name     string
		before   int
		findings int
	}{
		{"inside window", 9, 0},
		{"outside window", 8, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := config.Rule{
				RuleID: "decoded-near-match",
				Regex:  regexp.MustCompile(`decoded-secret-[A-Z]{20}`),
				Filter: fmt.Sprintf(`let matchContext = finding["fragment_raw"][max(finding["match_start_idx"] - %d, 0):finding["match_end_idx"]]; filter.containsAny(matchContext, ["provider"])`, tc.before),
			}
			cfg := &config.Config{
				Rules: []config.Rule{rule},
			}
			d := mustNewDetector(t, cfg, WithMaxDecodeDepth(1))

			require.Len(t, d.detectFragment(context.Background(), sources.Fragment{Raw: raw}), tc.findings)
		})
	}
}

func TestFilterUsesOriginalRegexMatchBounds(t *testing.T) {
	rule := config.Rule{
		RuleID: "original-match-bounds",
		Regex:  regexp.MustCompile("\nSECRET"),
		Filter: "let matchContext = finding[\"fragment_raw\"][finding[\"match_start_idx\"]:finding[\"match_end_idx\"]]; filter.matchesAny(matchContext, [`\\nSECRET$`])",
	}
	cfg := &config.Config{
		Rules: []config.Rule{rule},
	}

	require.Empty(t, mustNewDetector(t, cfg).detectFragment(context.Background(), sources.Fragment{Raw: "prefix\nSECRET"}))
}

func TestFilterContextCanStayOnMatchLine(t *testing.T) {
	rule := config.Rule{
		RuleID: "line-context",
		Regex:  regexp.MustCompile(`SECRET`),
		Filter: `let matchContext = finding["fragment_raw"][finding["match_line_start_idx"]:finding["match_line_end_idx"]]; filter.containsAny(matchContext, ["other-line"])`,
	}
	cfg := &config.Config{
		Rules: []config.Rule{rule},
	}

	require.Len(t, mustNewDetector(t, cfg).detectFragment(context.Background(), sources.Fragment{Raw: "other-line\nSECRET\nother-line"}), 1)
}

func TestDetect(t *testing.T) {
	tests := map[string]struct {
		cfgName  string
		fragment sources.Fragment
		// NOTE: for expected findings, all line numbers will be 0
		// because line deltas are added _after_ the finding is created.
		// I.e., if the finding is from a --no-git file, the line number will be
		// increase by 1 in DetectFromFiles(). If the finding is from git,
		// the line number will be increased by the patch delta.
		expectedFindings  []report.Finding
		wantError         error
		expectedAuxOutput string
	}{
		// General
		"valid allow comment (1)": {
			cfgName: "simple",
			fragment: sources.Fragment{
				Raw: `awsToken := \"AKIALALEMEL33243OKIA\ // gitleaks:allow"`,
				Attributes: map[string]string{
					sources.AttrPath: "tmp.go",
				},
			},
		},
		"valid allow comment (2)": {
			cfgName: "simple",
			fragment: sources.Fragment{
				Raw: `awsToken := \

		        \"AKIALALEMEL33243OKIA\ // gitleaks:allow"

		        `,
				Attributes: map[string]string{
					sources.AttrPath: "tmp.go",
				},
			},
		},
		"invalid allow comment": {
			cfgName: "simple",
			fragment: sources.Fragment{
				Raw: `awsToken := \"AKIALALEMEL33243OKIA\"

		                // gitleaks:allow"

		                `,
				Attributes: map[string]string{
					sources.AttrPath: "tmp.go",
				},
			},
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					Secret:      "AKIALALEMEL33243OKIA",
					Match:       "AKIALALEMEL33243OKIA",
					Line:        "awsToken := \\\"AKIALALEMEL33243OKIA\\\"\n",
					RuleID:      "aws-access-key",
					Tags:        []string{"key", "AWS"},
					Location: report.Location{
						StartLine:   1,
						EndLine:     1,
						StartColumn: 15,
						EndColumn:   34,
					},
				},
			},
		},
		"detect finding - aws": {
			cfgName: "simple",
			fragment: sources.Fragment{
				Raw: `awsToken := \"AKIALALEMEL33843OLIA\"`,
				Attributes: map[string]string{
					sources.AttrPath: "tmp.go",
				},
			},
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Line:        `awsToken := \"AKIALALEMEL33843OLIA\"`,
					Match:       "AKIALALEMEL33843OLIA",
					Secret:      "AKIALALEMEL33843OLIA",
					Location: report.Location{
						StartLine:   1,
						EndLine:     1,
						StartColumn: 15,
						EndColumn:   34,
					},
					Tags: []string{"key", "AWS"},
				},
			},
		},
		// Multiple instances of the same secret on a single line must produce
		// findings with distinct StartColumn values pointing to each occurrence.
		"detect finding - duplicate secret on same line": {
			cfgName: "simple",
			fragment: sources.Fragment{
				Raw: `#ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij...ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`,
				Attributes: map[string]string{
					sources.AttrPath: "tmp.go",
				},
			},
			expectedFindings: []report.Finding{
				{
					RuleID:      "github-pat",
					Description: "Github Personal Access Token",
					Line:        `#ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij...ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`,
					Match:       "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
					Secret:      "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
					Location: report.Location{
						StartLine:   1,
						EndLine:     1,
						StartColumn: 2,
						EndColumn:   41,
					},
					Tags: []string{"key", "Github"},
				},
				{
					RuleID:      "github-pat",
					Description: "Github Personal Access Token",
					Line:        `#ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij...ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`,
					Match:       "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
					Secret:      "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
					Location: report.Location{
						StartLine:   1,
						EndLine:     1,
						StartColumn: 45,
						EndColumn:   84,
					},
					Tags: []string{"key", "Github"},
				},
			},
		},

		"detect finding - sidekiq env var": {
			cfgName: "simple",
			fragment: sources.Fragment{
				Raw: `export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;`,
				Attributes: map[string]string{
					sources.AttrPath: "tmp.sh",
				},
			},
			expectedFindings: []report.Finding{
				{
					RuleID:      "sidekiq-secret",
					Description: "Sidekiq Secret",
					Line:        `export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;`,
					Match:       "BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;",
					Secret:      "cafebabe:deadbeef",
					Location: report.Location{
						StartLine:   1,
						EndLine:     1,
						StartColumn: 8,
						EndColumn:   60,
					},
					Tags: []string{},
				},
			},
		},
		"detect finding - sidekiq env var, semicolon": {
			cfgName: "simple",
			fragment: sources.Fragment{
				Raw: `echo hello1; export BUNDLE_ENTERPRISE__CONTRIBSYS__COM="cafebabe:deadbeef" && echo hello2`,
				Attributes: map[string]string{
					sources.AttrPath: "tmp.sh",
				},
			},
			expectedFindings: []report.Finding{
				{
					RuleID:      "sidekiq-secret",
					Description: "Sidekiq Secret",
					Line:        `echo hello1; export BUNDLE_ENTERPRISE__CONTRIBSYS__COM="cafebabe:deadbeef" && echo hello2`,
					Match:       "BUNDLE_ENTERPRISE__CONTRIBSYS__COM=\"cafebabe:deadbeef\"",
					Secret:      "cafebabe:deadbeef",
					Location: report.Location{
						StartLine:   1,
						EndLine:     1,
						StartColumn: 21,
						EndColumn:   74,
					},
					Tags: []string{},
				},
			},
		},
		"detect finding - sidekiq url": {
			cfgName: "simple",
			fragment: sources.Fragment{
				Raw: `url = "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80/path?param1=true&param2=false#heading1"`,
				Attributes: map[string]string{
					sources.AttrPath: "tmp.sh",
				},
			},
			expectedFindings: []report.Finding{
				{
					RuleID:      "sidekiq-sensitive-url",
					Description: "Sidekiq Sensitive URL",
					Line:        `url = "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80/path?param1=true&param2=false#heading1"`,
					Match:       "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:",
					Secret:      "cafeb4b3:d3adb33f",
					Location: report.Location{
						StartLine:   1,
						EndLine:     1,
						StartColumn: 8,
						EndColumn:   58,
					},
					Tags: []string{},
				},
			},
		},
		"ignore finding - our config file": {
			cfgName: "simple",
			fragment: sources.Fragment{
				Raw:        `awsToken := \"AKIALALEMEL33243OLIA\"`,
				Attributes: map[string]string{sources.AttrPath: filepath.Join(configPath, "simple.toml")},
			},
		},
		"ignore finding - doesn't match path": {
			cfgName: "generic_with_py_path",
			fragment: sources.Fragment{
				Raw: `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				Attributes: map[string]string{
					sources.AttrPath: "tmp.go",
				},
			},
		},
		"detect finding - matches path,regex,entropy": {
			cfgName: "generic_with_py_path",
			fragment: sources.Fragment{
				Raw: `const Discord_Public_Key = "e8322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				Attributes: map[string]string{
					sources.AttrPath: "tmp.py",
				},
			},
			expectedFindings: []report.Finding{
				{
					RuleID:      "generic-api-key",
					Description: "Generic API Key",
					Line:        `const Discord_Public_Key = "e8322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
					Match:       "Key = \"e8322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5\"",
					Secret:      "e8322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5",
					Location: report.Location{
						StartLine:   1,
						EndLine:     1,
						StartColumn: 22,
						EndColumn:   93,
					},
					Tags: []string{},
				},
			},
		},
		"ignore finding - global filter": {
			cfgName: "generic_with_py_path",
			fragment: sources.Fragment{
				Raw: `const Discord_Public_Key = "load2523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				Attributes: map[string]string{
					sources.AttrPath: "tmp.py",
				},
			},
		},

		// Rule
		"rule - ignore path": {
			cfgName: "valid/rule_path_only",
			fragment: sources.Fragment{
				Raw: `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				Attributes: map[string]string{
					sources.AttrPath: ".baseline.json",
				},
			},
		},
		"rule - detect path ": {
			cfgName: "valid/rule_path_only",
			fragment: sources.Fragment{
				Raw: `const Discord_Public_Key = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`,
				Attributes: map[string]string{
					sources.AttrPath: "tmp.py",
				},
			},
			expectedFindings: []report.Finding{
				{
					Description: "Python Files",
					Match:       "file detected: tmp.py",

					RuleID: "python-files-only",
					Tags:   []string{},
				},
			},
		},
		"fragment level composite": {
			cfgName: "composite",
			fragment: sources.Fragment{
				Raw: multili,
			},
			expectedFindings: []report.Finding{
				{
					Description: "Primary rule",
					RuleID:      "primary-rule",
					Location: report.Location{
						StartLine:   6,
						EndLine:     6,
						StartColumn: 4,
						EndColumn:   25,
					},
					Line:   "\t\t\tpassword = \"secret123\"\n",
					Match:  `password = "secret123"`,
					Secret: "secret123",
					Tags:   []string{},
				},
			},
			expectedAuxOutput: "│ components:\n│   -  username-rule:2 ...... admin\n",
		},
		// Decoding
		"detect encoded": {
			cfgName: "encoded",
			fragment: sources.Fragment{
				Raw: encodedTestValues,
				Attributes: map[string]string{
					sources.AttrPath: "tmp.go",
				},
			},
			expectedFindings: []report.Finding{
				{ // Plain text key captured by normal rule
					Description: "Private Key",
					Secret:      "-----BEGIN PRIVATE KEY-----\n135f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb\nu+QDkg0spw==\n-----END PRIVATE KEY-----",
					Match:       "-----BEGIN PRIVATE KEY-----\n135f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb\nu+QDkg0spw==\n-----END PRIVATE KEY-----",
					Line:        "-----BEGIN PRIVATE KEY-----\n135f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb\nu+QDkg0spw==\n-----END PRIVATE KEY-----\n",
					RuleID:      "private-key",
					Tags:        []string{"key", "private"},
					Location: report.Location{
						StartLine:   3,
						EndLine:     6,
						StartColumn: 1,
						EndColumn:   25,
					},
				},
				{ // Encoded key captured by custom b64 regex rule
					Description: "Private Key",
					Secret:      "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCjQzNWYvYlJVQkhyYkhxTFkveFMzSTdPdGgrOHJnRyswdEJ3Zk1jYmswNVNneHE2UVV6U1lJUUFvcCtXdnNUd2syc1IrQzM4ZzBNbmIKdStRRGtnMHNwdz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K",
					Match:       "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCjQzNWYvYlJVQkhyYkhxTFkveFMzSTdPdGgrOHJnRyswdEJ3Zk1jYmswNVNneHE2UVV6U1lJUUFvcCtXdnNUd2syc1IrQzM4ZzBNbmIKdStRRGtnMHNwdz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K",
					Line:        "private_key: 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCjQzNWYvYlJVQkhyYkhxTFkveFMzSTdPdGgrOHJnRyswdEJ3Zk1jYmswNVNneHE2UVV6U1lJUUFvcCtXdnNUd2syc1IrQzM4ZzBNbmIKdStRRGtnMHNwdz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K'\n",
					RuleID:      "b64-encoded-private-key",
					Tags:        []string{"key", "private"},
					Location: report.Location{
						StartLine:   9,
						EndLine:     9,
						StartColumn: 15,
						EndColumn:   206,
					},
				},
				{ // Encoded key captured by plain text rule using the decoder
					Description: "Private Key",
					Secret:      "-----BEGIN PRIVATE KEY-----\n435f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb\nu+QDkg0spw==\n-----END PRIVATE KEY-----",
					Match:       "-----BEGIN PRIVATE KEY-----\n435f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb\nu+QDkg0spw==\n-----END PRIVATE KEY-----",
					Line:        "private_key: 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCjQzNWYvYlJVQkhyYkhxTFkveFMzSTdPdGgrOHJnRyswdEJ3Zk1jYmswNVNneHE2UVV6U1lJUUFvcCtXdnNUd2syc1IrQzM4ZzBNbmIKdStRRGtnMHNwdz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K'\n",
					RuleID:      "private-key",
					Tags:        []string{"key", "private", "decoded:base64", "decode-depth:1"},
					Location: report.Location{
						StartLine:   9,
						EndLine:     9,
						StartColumn: 15,
						EndColumn:   206,
					},
				},
				{ // Encoded Small secret at the end to make sure it's picked up by the decoding
					Description: "Small Secret",
					Secret:      "small-secret",
					Match:       "small-secret",
					Line:        "c21hbGwtc2VjcmV0\n",
					RuleID:      "small-secret",
					Tags:        []string{"small", "secret", "decoded:base64", "decode-depth:1"},
					Location: report.Location{
						StartLine:   16,
						EndLine:     16,
						StartColumn: 1,
						EndColumn:   16,
					},
				},
				{ // Secret where the decoded match goes outside the encoded value
					Description: "Overlapping",
					Secret:      "decoded-secret-value00",
					Match:       "secret=decoded-secret-value00",
					Line:        "secret=ZGVjb2RlZC1zZWNyZXQtdmFsdWUwMA==\n",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:base64", "decode-depth:1"},
					Location: report.Location{
						StartLine:   19,
						EndLine:     19,
						StartColumn: 1,
						EndColumn:   39,
					},
				},
				{ // This confirms the rule is detected without a filter.
					Description: "Make sure this would be detected without a filter",
					Secret:      "lRqBK-z5kf4-please-ignore-me-X-XIJM2Pddw",
					Match:       "password=\"lRqBK-z5kf4-please-ignore-me-X-XIJM2Pddw\"",
					Line:        "password=\"bFJxQkstejVrZjQtcGxlYXNlLWlnbm9yZS1tZS1YLVhJSk0yUGRkdw==\"\n",
					RuleID:      "decoded-password-dont-ignore",
					Tags:        []string{"decode-ignore", "decoded:base64", "decode-depth:1"},
					Location: report.Location{
						StartLine:   24,
						EndLine:     24,
						StartColumn: 1,
						EndColumn:   67,
					},
				},
				{ // Hex encoded data check
					Description: "Overlapping",
					Secret:      "decoded-secret-valuevHEX",
					Match:       "secret=decoded-secret-valuevHEX",
					Line:        "secret=6465636F6465642D7365637265742D76616C756576484558\n",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:hex", "decode-depth:1"},
					Location: report.Location{
						StartLine:   27,
						EndLine:     27,
						StartColumn: 1,
						EndColumn:   55,
					},
				},
				{ // handle partial encoded percent data
					Description: "Overlapping",
					Secret:      "decoded-secret-valuev2",
					Match:       "secret=decoded-secret-valuev2",
					Line:        "secret=decoded-%73%65%63%72%65%74-valuev2\n",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:percent", "decode-depth:1"},
					Location: report.Location{
						StartLine:   31,
						EndLine:     31,
						StartColumn: 1,
						EndColumn:   41,
					},
				},
				{ // handle partial encoded percent data
					Description: "Overlapping",
					Secret:      "decoded-secret-valuev3",
					Match:       "secret=decoded-secret-valuev3",
					Line:        "secret=%64%65coded-%73%65%63%72%65%74-valuev3\n",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:percent", "decode-depth:1"},
					Location: report.Location{
						StartLine:   33,
						EndLine:     33,
						StartColumn: 1,
						EndColumn:   45,
					},
				},
				{ // Encoded AWS config with a access key id inside a JWT
					Description: "AWS IAM Unique Identifier",
					Secret:      "ASIAIOSFODNN7LXM10JI",
					Match:       " ASIAIOSFODNN7LXM10JI",
					Line:        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiY29uZmlnIjoiVzJSbFptRjFiSFJkQ25KbFoybHZiaUE5SUhWekxXVmhjM1F0TWdwaGQzTmZZV05qWlhOelgydGxlVjlwWkNBOUlFRlRTVUZKVDFOR1QwUk9UamRNV0UweE1FcEpDbUYzYzE5elpXTnlaWFJmWVdOalpYTnpYMnRsZVNBOUlIZEtZV3h5V0ZWMGJrWkZUVWt2U3pkTlJFVk9SeTlpVUhoU1ptbERXVVZHVlVORWJFVllNVUVLIiwiaWF0IjoxNTE2MjM5MDIyfQ.8gxviXEOuIBQk2LvTYHSf-wXVhnEKC3h4yM5nlOF4zA\n",
					RuleID:      "aws-iam-unique-identifier",
					Tags:        []string{"aws", "identifier", "decoded:base64", "decode-depth:2"},
					Location: report.Location{
						StartLine:   12,
						EndLine:     12,
						StartColumn: 38,
						EndColumn:   343,
					},
				},
				{ // Encoded AWS config with a secret access key inside a JWT
					Description: "AWS Secret Access Key",
					Secret:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEFUCDlEX1A",
					Match:       "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEFUCDlEX1A",
					Line:        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiY29uZmlnIjoiVzJSbFptRjFiSFJkQ25KbFoybHZiaUE5SUhWekxXVmhjM1F0TWdwaGQzTmZZV05qWlhOelgydGxlVjlwWkNBOUlFRlRTVUZKVDFOR1QwUk9UamRNV0UweE1FcEpDbUYzYzE5elpXTnlaWFJmWVdOalpYTnpYMnRsZVNBOUlIZEtZV3h5V0ZWMGJrWkZUVWt2U3pkTlJFVk9SeTlpVUhoU1ptbERXVVZHVlVORWJFVllNVUVLIiwiaWF0IjoxNTE2MjM5MDIyfQ.8gxviXEOuIBQk2LvTYHSf-wXVhnEKC3h4yM5nlOF4zA\n",
					RuleID:      "aws-secret-access-key",
					Tags:        []string{"aws", "secret", "decoded:base64", "decode-depth:2"},
					Location: report.Location{
						StartLine:   12,
						EndLine:     12,
						StartColumn: 38,
						EndColumn:   343,
					},
				},
				{ // Secret where the decoded match goes outside the encoded value and then encoded again
					Description: "Overlapping",
					Secret:      "decoded-secret-value",
					Match:       "secret=decoded-secret-value",
					Line:        "c2VjcmV0PVpHVmpiMlJsWkMxelpXTnlaWFF0ZG1Gc2RXVT0=\n",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:base64", "decode-depth:2"},
					Location: report.Location{
						StartLine:   21,
						EndLine:     21,
						StartColumn: 1,
						EndColumn:   48,
					},
				},
				{ // handle encodings that touch eachother
					Description: "Overlapping",
					Secret:      "decoded-secret-valuev5",
					Match:       "secret=decoded-secret-valuev5",
					Line:        "secret%3d6465636F6465642D7365637265742D76616C75657635\n",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:percent", "decoded:hex", "decode-depth:2"},
					Location: report.Location{
						StartLine:   41,
						EndLine:     41,
						StartColumn: 1,
						EndColumn:   53,
					},
				},
				{ // handle partial encoded percent data465642D7365637265742D76616C75657635
					Description: "Overlapping",
					Secret:      "decoded-secret-valuev4",
					Match:       "secret=decoded-secret-valuev4",
					Line:        "c2VjcmV0PVpHVmpiMl%4AsWkMxelpXTnlaWFF0ZG1Gc2RXVjJOQT09\n",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:percent", "decoded:base64", "decode-depth:3"},
					Location: report.Location{
						StartLine:   39,
						EndLine:     39,
						StartColumn: 1,
						EndColumn:   54,
					},
				},
				{ // multiple percent encodings in a single layer base64
					Description: "Overlapping",
					Secret:      "decoded-secret-valuex86",
					Match:       "secret=decoded-secret-valuex86",
					Line:        "secret=ZGVjb2%52lZC1zZWNyZXQtdm%46sdWV4ODY=  # ends in x86\n",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:percent", "decoded:base64", "decode-depth:2"},
					Location: report.Location{
						StartLine:   43,
						EndLine:     43,
						StartColumn: 1,
						EndColumn:   43,
					},
				},
				{ // base64 encoded partially percent encoded value
					Description: "Overlapping",
					Secret:      "decoded-secret-value",
					Match:       "secret=decoded-secret-value",
					Line:        "secret=ZGVjb2RlZC0lNzMlNjUlNjMlNzIlNjUlNzQtdmFsdWU=\n",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:percent", "decoded:base64", "decode-depth:2"},
					Location: report.Location{
						StartLine:   45,
						EndLine:     45,
						StartColumn: 1,
						EndColumn:   51,
					},
				},
				{ // one of the lines above that went through... a lot
					Description: "Overlapping",
					Secret:      "decoded-secret-value",
					Match:       "secret=decoded-secret-value",
					Line:        "Look at this value: %4EjMzMjU2NkE2MzZENTYzMDUwNTY3MDQ4%4eTY2RDcwNjk0RDY5NTUzMTRENkQ3ODYx%25%34%65TE3QTQ2MzY1NzZDNjQ0RjY1NTY3MDU5NTU1ODUyNkI2MjUzNTUzMDRFNkU0RTZCNTYzMTU1MzkwQQ== # isn't it crazy?\n",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:percent", "decoded:hex", "decoded:base64", "decode-depth:7"},
					Location: report.Location{
						StartLine:   48,
						EndLine:     48,
						StartColumn: 21,
						EndColumn:   176,
					},
				},
				{ // Multi percent encode two random characters close to the bounds of the base64
					Description: "Overlapping",
					Secret:      "decoded-secret-value",
					Match:       "secret=decoded-secret-value",
					Line:        "secret=ZG%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%36%25%33%31%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%33%25%33%322RlZC1zZWNyZXQtd%25%36%64%25%34%36%25%37%33dWU=\n",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:percent", "decoded:base64", "decode-depth:5"},
					Location: report.Location{
						StartLine:   51,
						EndLine:     51,
						StartColumn: 1,
						EndColumn:   299,
					},
				},
				{ // The similar to the above but also touching the edge of the base64
					Description: "Overlapping",
					Secret:      "decoded-secret-value",
					Match:       "secret=decoded-secret-value",
					Line:        "secret=%25%35%61%25%34%37%25%35%36jb2RlZC1zZWNyZXQtdmFsdWU%25%32%35%25%33%33%25%36%34\n",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:percent", "decoded:base64", "decode-depth:4"},
					Location: report.Location{
						StartLine:   53,
						EndLine:     53,
						StartColumn: 1,
						EndColumn:   85,
					},
				},
				{ // The similar to the above but also touching and overlapping the base64
					Description: "Overlapping",
					Secret:      "decoded-secret-value",
					Match:       "secret=decoded-secret-value",
					Line:        "secret%3D%25%35%61%25%34%37%25%35%36jb2RlZC1zZWNyZXQtdmFsdWU%25%32%35%25%33%33%25%36%34\n",
					RuleID:      "overlapping",
					Tags:        []string{"overlapping", "decoded:percent", "decoded:base64", "decode-depth:4"},
					Location: report.Location{
						StartLine:   55,
						EndLine:     55,
						StartColumn: 1,
						EndColumn:   87,
					},
				},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := loadTestConfig(t, tt.cfgName)
			cfg.Path = filepath.Join(configPath, tt.cfgName+".toml")
			assert.Nil(t, tt.wantError)
			d := mustNewDetector(t, cfg, WithMaxDecodeDepth(maxDecodeDepth))
			findings := d.detectFragment(context.Background(), tt.fragment)

			compare(t, findings, tt.expectedFindings)

			// extremely goofy way to test auxiliary findings
			// capture stdout and print that sonabitch
			// TODO
			if tt.expectedAuxOutput != "" {
				capturedOutput := captureStdout(func() {
					for _, finding := range findings {
						finding.PrintComponentFindings(false, 0)
					}
				})

				// Clean up the output for comparison (remove ANSI color codes)
				cleanOutput := stripANSI(capturedOutput)
				expectedClean := stripANSI(tt.expectedAuxOutput)

				assert.Equal(t, expectedClean, cleanOutput, "Auxiliary output should match")
			}

		})
	}
}

func stripANSI(s string) string {
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return ansiRegex.ReplaceAllString(s, "")
}

func captureStdout(f func()) string {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func expectedAWSFinding(line string, location report.Location) report.Finding {
	return report.Finding{
		RuleID:      "aws-access-key",
		Description: "AWS Access Key",
		Location:    location,
		Line:        line,
		Match:       "AKIALALEMEL33243OLIA",
		Secret:      "AKIALALEMEL33243OLIA",
		Tags:        []string{"key", "AWS"},
	}
}

// TestFromGit tests the FromGit function
func TestFromGit(t *testing.T) {
	// TODO: Fix this test on windows.
	if runtime.GOOS == "windows" {
		t.Skipf("TODO: this fails on Windows: [git] fatal: bad object refs/remotes/origin/main?")
		return
	}
	tests := []struct {
		cfgName          string
		source           string
		logOpts          string
		expectedFindings []report.Finding
	}{
		{
			source:  filepath.Join(repoBasePath, "small"),
			cfgName: "simple", // the remote url is `git@github.com:gitleaks/test.git`
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 18,
						EndColumn:   37,
					},
					Line:   "    awsToken := \"AKIALALEMEL33243OLIA\"\n",
					Secret: "AKIALALEMEL33243OLIA",
					Match:  "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   9,
						EndLine:     9,
						StartColumn: 16,
						EndColumn:   35,
					},
					Secret: "AKIALALEMEL33243OLIA",
					Match:  "AKIALALEMEL33243OLIA",
					Line:   "\taws_token := \"AKIALALEMEL33243OLIA\"\n",
					Tags:   []string{"key", "AWS"},
				},
				expectedAWSFinding("\tawsToken := \"AKIALALEMEL33243OLIA\"\n", report.Location{
					StartLine: 20, EndLine: 20, StartColumn: 15, EndColumn: 34,
				}),
				expectedAWSFinding("\tawsToken := \"AKIALALEMEL33243OLIA\"\n", report.Location{
					StartLine: 20, EndLine: 20, StartColumn: 15, EndColumn: 34,
				}),
			},
		},
		{
			source:  filepath.Join(repoBasePath, "small"),
			logOpts: "--all foo...",
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   9,
						EndLine:     9,
						StartColumn: 16,
						EndColumn:   35,
					},
					Secret: "AKIALALEMEL33243OLIA",
					Line:   "\taws_token := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				expectedAWSFinding("\tawsToken := \"AKIALALEMEL33243OLIA\"\n", report.Location{
					StartLine: 20, EndLine: 20, StartColumn: 15, EndColumn: 34,
				}),
				expectedAWSFinding("\tawsToken := \"AKIALALEMEL33243OLIA\"\n", report.Location{
					StartLine: 20, EndLine: 20, StartColumn: 15, EndColumn: 34,
				}),
			},
		},
		{
			source:  filepath.Join(repoBasePath, "archives"),
			cfgName: "archives",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
			},
		},
	}

	moveDotGit(t, "dotGit", ".git")
	defer moveDotGit(t, ".git", "dotGit")

	for _, tt := range tests {
		t.Run(strings.Join([]string{tt.cfgName, tt.source, tt.logOpts}, "/"), func(t *testing.T) {
			cfg := loadTestConfig(t, "simple")
			detector := mustNewDetector(t, cfg)

			gitCmd, err := sources.NewGitLogCmd(tt.source, tt.logOpts)
			require.NoError(t, err)
			platform, remoteURL := sources.ResolveRemote(t.Context(), scm.UnknownPlatform, tt.source)
			findings, err := collectSourceFindings(
				t.Context(), detector,

				&sources.Git{
					Cmd:             gitCmd,
					ShouldSkip:      detector.SkipFunc(),
					Platform:        platform,
					RemoteURL:       remoteURL,
					MaxArchiveDepth: 8,
				})

			require.NoError(t, err)

			for _, f := range findings {
				f.Match = "" // remove lines cause copying and pasting them has some wack formatting
			}
			assert.ElementsMatch(t, stripFindingAttributes(tt.expectedFindings), stripFindingAttributes(findings))
		})
	}
}

func TestFromGitStaged(t *testing.T) {
	tests := []struct {
		cfgName          string
		source           string
		logOpts          string
		expectedFindings []report.Finding
	}{
		{
			source:  filepath.Join(repoBasePath, "staged"),
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   7,
						EndLine:     7,
						StartColumn: 17,
						EndColumn:   36,
					},
					Line:   "\taws_token2 := \"AKIALALEMEL33243OLIA\" // this one is not\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags: []string{
						"key",
						"AWS",
					},
				},
				expectedAWSFinding(
					"\taws_token := \"AKIALALEMEL33243OLIA\"  // fingerprint of that secret is added to .gitleaksignore\n",
					report.Location{StartLine: 6, EndLine: 6, StartColumn: 16, EndColumn: 35},
				),
			},
		},
	}

	moveDotGit(t, "dotGit", ".git")
	defer moveDotGit(t, ".git", "dotGit")
	for _, tt := range tests {
		cfg := loadTestConfig(t, "simple")
		detector := mustNewDetector(t, cfg)
		gitCmd, err := sources.NewGitDiffCmd(tt.source, true)
		require.NoError(t, err)
		platform, remoteURL := sources.ResolveRemote(t.Context(), scm.UnknownPlatform, tt.source)
		findings, err := collectSourceFindings(
			t.Context(), detector,

			&sources.Git{
				Cmd:        gitCmd,
				ShouldSkip: detector.SkipFunc(),
				Platform:   platform,
				RemoteURL:  remoteURL,
			})

		require.NoError(t, err)

		for _, f := range findings {
			f.Match = "" // remove lines cause copying and pasting them has some wack formatting
		}
		assert.ElementsMatch(t, stripFindingAttributes(tt.expectedFindings), stripFindingAttributes(findings))
	}
}

// TestFromFiles tests the FromFiles function
func TestFromFiles(t *testing.T) {
	tests := []struct {
		cfgName          string
		source           string
		expectedFindings []report.Finding
	}{
		{
			source:  filepath.Join(repoBasePath, "nogit"),
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				expectedAWSFinding("\tawsToken := \"AKIALALEMEL33243OLIA\"\n", report.Location{
					StartLine: 20, EndLine: 20, StartColumn: 15, EndColumn: 34,
				}),
			},
		},
		{
			source:  filepath.Join(repoBasePath, "nogit", "main.go"),
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
			},
		},
		{
			source:  filepath.Join(repoBasePath, "nogit", "api.go"),
			cfgName: "simple",
			expectedFindings: []report.Finding{
				expectedAWSFinding("\tawsToken := \"AKIALALEMEL33243OLIA\"\n", report.Location{
					StartLine: 20, EndLine: 20, StartColumn: 15, EndColumn: 34,
				}),
			},
		},
		{
			source:  filepath.Join(repoBasePath, "nogit", ".env.prod"),
			cfgName: "generic",
			expectedFindings: []report.Finding{
				{
					RuleID:      "generic-api-key",
					Description: "Generic API Key",
					Location: report.Location{
						StartLine:   4,
						EndLine:     4,
						StartColumn: 4,
						EndColumn:   34,
					},
					Line:   "DB_PASSWORD=8ae31cacf141669ddfb5da\n",
					Match:  "PASSWORD=8ae31cacf141669ddfb5da",
					Secret: "8ae31cacf141669ddfb5da",
					Tags:   []string{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.cfgName+" - "+tt.source, func(t *testing.T) {
			cfg := loadTestConfig(t, tt.cfgName)
			detector := mustNewDetector(t, cfg)

			findings, err := collectSourceFindings(
				t.Context(), detector,

				&sources.Files{
					ShouldSkip:     detector.SkipFunc(),
					FollowSymlinks: true,
					Path:           tt.source,
				})

			require.NoError(t, err)

			normalizeFindings(findings)
			assert.ElementsMatch(t, stripFindingAttributes(tt.expectedFindings), stripFindingAttributes(findings))
		})
	}
}

func TestDetectWithArchives(t *testing.T) {
	tests := []struct {
		cfgName          string
		source           string
		expireContext    bool
		expectedFindings []report.Finding
	}{
		{
			source:           filepath.Join(archivesBasePath, "this-path-does-not-exist"),
			cfgName:          "archives",
			expectedFindings: []report.Finding{},
		},
		{
			source:  filepath.Join(archivesBasePath, "files"),
			cfgName: "archives",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
			},
		},
		{
			source:  filepath.Join(archivesBasePath, "files.7z"),
			cfgName: "archives",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
			},
		},
		{
			source:  filepath.Join(archivesBasePath, "files.tar"),
			cfgName: "archives",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
			},
		},
		{
			source:  filepath.Join(archivesBasePath, "files.tar.xz"),
			cfgName: "archives",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
			},
		},
		{
			source:  filepath.Join(archivesBasePath, "files.tar.zst"),
			cfgName: "archives",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
			},
		},
		{
			source:  filepath.Join(archivesBasePath, "files.zip"),
			cfgName: "archives",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
			},
		},
		{
			source:  filepath.Join(archivesBasePath, "nested.tar.gz"),
			cfgName: "archives",
			expectedFindings: []report.Finding{
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
				{
					RuleID:      "aws-access-key",
					Description: "AWS Access Key",
					Location: report.Location{
						StartLine:   20,
						EndLine:     20,
						StartColumn: 15,
						EndColumn:   34,
					},
					Line:   "\tawsToken := \"AKIALALEMEL33243OLIA\"\n",
					Match:  "AKIALALEMEL33243OLIA",
					Secret: "AKIALALEMEL33243OLIA",
					Tags:   []string{"key", "AWS"},
				},
			},
		},
		{
			source:           filepath.Join(archivesBasePath, "nested.tar.gz"),
			cfgName:          "archives",
			expireContext:    true,
			expectedFindings: []report.Finding{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.cfgName+" - "+tt.source, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.expireContext {
				cancel()
			}

			cfg := loadTestConfig(t, tt.cfgName)
			detector := mustNewDetector(t, cfg)
			findings, err := collectSourceFindings(
				ctx, detector,
				&sources.Files{
					Path:            tt.source,
					ShouldSkip:      detector.SkipFunc(),
					MaxArchiveDepth: 8,
				})

			if tt.expireContext {
				require.NoError(t, err)
			} else {
				cancel()
				require.NoError(t, err)
			}

			normalizeFindings(findings)
			assert.ElementsMatch(t, stripFindingAttributes(tt.expectedFindings), stripFindingAttributes(findings))
		})
	}

}

func TestDetectWithSymlinks(t *testing.T) {
	// TODO: Fix this test on windows.
	if runtime.GOOS == "windows" {
		t.Skipf("TODO: this returns no results on windows, I'm not sure why.")
		return
	}

	tests := []struct {
		cfgName          string
		source           string
		expectedFindings []report.Finding
	}{
		{
			source:  filepath.Join(repoBasePath, "symlinks/file_symlink"),
			cfgName: "simple",
			expectedFindings: []report.Finding{
				{
					RuleID:      "apkey",
					Description: "Asymmetric Private Key",
					Location: report.Location{
						StartLine:   1,
						EndLine:     1,
						StartColumn: 1,
						EndColumn:   35,
					},
					Match:  "-----BEGIN OPENSSH PRIVATE KEY-----",
					Secret: "-----BEGIN OPENSSH PRIVATE KEY-----",
					Line:   "-----BEGIN OPENSSH PRIVATE KEY-----\n",
					Tags:   []string{"key", "AsymmetricPrivateKey"},
				},
			},
		},
	}

	for _, tt := range tests {
		cfg := loadTestConfig(t, "simple")
		detector := mustNewDetector(t, cfg)
		findings, err := collectSourceFindings(
			t.Context(), detector,

			&sources.Files{
				ShouldSkip:     detector.SkipFunc(),
				FollowSymlinks: true,
				Path:           tt.source,
			})

		require.NoError(t, err)
		assert.ElementsMatch(t, stripFindingAttributes(tt.expectedFindings), stripFindingAttributes(findings))
	}
}

func moveDotGit(t *testing.T, from, to string) {
	t.Helper()

	repoDirs, err := os.ReadDir("../testdata/repos")
	require.NoError(t, err)
	for _, dir := range repoDirs {
		if to == ".git" {
			_, err := os.Stat(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), "dotGit"))
			if os.IsNotExist(err) {
				// dont want to delete the only copy of .git accidentally
				continue
			}
			_ = os.RemoveAll(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), ".git"))
		}
		if !dir.IsDir() {
			continue
		}
		_, err := os.Stat(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), from))
		if os.IsNotExist(err) {
			continue
		}

		err = os.Rename(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), from),
			fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), to))
		require.NoError(t, err)
	}
}

func TestWindowsFileSeparator_RulePath(t *testing.T) {
	unixRule := config.Rule{
		RuleID: "test-rule",
		Path:   regexp.MustCompile(`(^|/)\.m2/settings\.xml`),
	}
	windowsRule := config.Rule{
		RuleID: "test-rule",
		Path:   regexp.MustCompile(`(^|\\)\.m2\\settings\.xml`),
	}
	expected := []report.Finding{
		{
			RuleID: "test-rule",
			Match:  "file detected: .m2/settings.xml",
			Tags:   []string{},
		},
	}
	tests := map[string]struct {
		fragment sources.Fragment
		rule     config.Rule
		expected []report.Finding
	}{
		// unix rule
		"unix rule - unix path separator": {
			fragment: sources.Fragment{
				Attributes: map[string]string{
					sources.AttrPath: `.m2/settings.xml`,
				},
			},
			rule:     unixRule,
			expected: expected,
		},
		"unix rule - windows path separator": {
			fragment: sources.Fragment{
				Attributes: map[string]string{
					sources.AttrPath: `.m2/settings.xml`,
				},
			},
			rule:     unixRule,
			expected: expected,
		},
		"unix regex+path rule - windows path separator": {
			fragment: sources.Fragment{
				Raw: `<password>s3cr3t</password>`,
				Attributes: map[string]string{
					sources.AttrPath: `.m2/settings.xml`,
				},
			},
			rule: config.Rule{
				RuleID: "test-rule",
				Regex:  regexp.MustCompile(`<password>(.+?)</password>`),
				Path:   regexp.MustCompile(`(^|/)\.m2/settings\.xml`),
			},
			expected: []report.Finding{
				{
					RuleID: "test-rule",
					Location: report.Location{
						StartLine:   1,
						EndLine:     1,
						StartColumn: 1,
						EndColumn:   27,
					},
					Line:   "<password>s3cr3t</password>",
					Match:  "<password>s3cr3t</password>",
					Secret: "s3cr3t",
					Tags:   []string{},
				},
			},
		},

		// windows rule
		"windows rule - unix path separator": {
			fragment: sources.Fragment{
				Attributes: map[string]string{
					sources.AttrPath: `.m2/settings.xml`,
				},
			},
			rule: windowsRule,
			// This never worked, and continues not to work.
			// Paths should be normalized to use Unix file separators.
			expected: nil,
		},
		"windows rule - windows path separator": {
			fragment: sources.Fragment{
				Attributes: map[string]string{
					sources.AttrPath: `.m2/settings.xml`,
				},
			},
			rule: windowsRule,
			// Paths are normalized to use Unix separators before detection.
			expected: nil,
		},
		"windows regex+path rule - windows path separator": {
			fragment: sources.Fragment{
				Raw: `<password>s3cr3t</password>`,
				Attributes: map[string]string{
					sources.AttrPath: `.m2/settings.xml`,
				},
			},
			rule: config.Rule{
				RuleID: "test-rule",
				Regex:  regexp.MustCompile(`<password>(.+?)</password>`),
				Path:   regexp.MustCompile(`(^|\\)\.m2\\settings\.xml`),
			},
			// Paths are normalized to use Unix separators before detection.
			expected: nil,
		},
	}

	d := newDefaultTestDetector(t)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			actual := d.detectFragmentWithRule(nil, test.fragment, test.fragment.Raw, test.rule, []*codec.EncodedSegment{}, nil)
			compare(t, actual, test.expected)
		})
	}
}
