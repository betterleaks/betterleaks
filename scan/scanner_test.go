package scan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/fingerprint"
	"github.com/betterleaks/betterleaks/v2/internal/codec"
	"github.com/betterleaks/betterleaks/v2/internal/contextwindow"
	"github.com/betterleaks/betterleaks/v2/internal/ruletiming"
	"github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/regexp/re2"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/prefilter"
	"github.com/betterleaks/betterleaks/v2/sources/scm"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func newCancelOnSecondCheck() *cancelOnSecondCheck {
	closed := make(chan struct{})
	close(closed)
	return &cancelOnSecondCheck{open: make(chan struct{}), closed: closed}
}

func normalizeFindings(fs []report.Finding) {
	// TODO: Temporary mitigation.
	// https://github.com/gitleaks/gitleaks/issues/1641
	for i := range fs {
		f := &fs[i]
		f.Match.Line = strings.ReplaceAll(f.Match.Line, "\r", "")
		before := len(f.Match.Full)
		f.Match.Full = strings.ReplaceAll(f.Match.Full, "\r", "")
		after := len(f.Match.Full)
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

func newDefaultTestScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg, err := config.Default()
	require.NoError(t, err)
	return mustNew(t, cfg)
}

func mustNew(t *testing.T, cfg *config.Config, options ...Option) *Scanner {
	t.Helper()
	scanner, err := New(cfg, options...)
	require.NoError(t, err)
	return scanner
}

func testConfig() *config.Config {
	return &config.Config{Rules: []config.Rule{{
		ID:    "test-secret",
		Regex: `secret-[a-z]+`,
	}}}
}

func TestIgnoredFingerprintsUseExtractedSecret(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{{
		ID: "token", Regex: `token=(secret-[a-z]+)`, SecretGroup: 1,
	}}}
	ignored := fingerprint.Sum([]byte("secret-ignored"))
	for _, input := range []string{
		"token=secret-ignored token=secret-visible",
		base64.StdEncoding.EncodeToString([]byte("token=secret-ignored token=secret-visible")),
	} {
		baseline := mustNew(t, cfg, WithMaxDecodeDepth(2))
		require.Len(t, baseline.ScanString(input), 2)
		scanner := mustNew(t, cfg, WithMaxDecodeDepth(2), WithIgnoredFingerprints(ignored))
		findings := scanner.ScanString(input)
		require.Len(t, findings, 1)
		assert.Equal(t, "secret-visible", findings[0].Match.Value)
	}
	// A fingerprint of the entire regex match must not suppress its capture.
	scanner := mustNew(t, cfg, WithIgnoredFingerprints(fingerprint.Sum([]byte("token=secret-ignored"))))
	require.Len(t, scanner.ScanString("token=secret-ignored"), 1)
}

func TestIgnoredFingerprintsPreserveComponents(t *testing.T) {
	for _, optional := range []bool{false, true} {
		for _, skipReport := range []bool{false, true} {
			cfg := &config.Config{Rules: []config.Rule{
				{ID: "primary", Regex: `primary-token`, Components: []config.Component{{RuleID: "component", Within: "2L", Optional: optional}}},
				{ID: "component", Regex: `companion-token`, SkipReport: skipReport},
			}}
			scanner := mustNew(t, cfg, WithIgnoredFingerprints(fingerprint.Sum([]byte("companion-token"))))
			findings := scanner.ScanString("primary-token companion-token")
			require.Len(t, findings, 1)
			assert.Equal(t, "primary", findings[0].RuleID)
			require.Len(t, findings[0].ComponentSets, 1)
			require.Len(t, findings[0].ComponentSets[0].Components, 1)
			assert.Equal(t, "companion-token", findings[0].ComponentSets[0].Components[0].Match.Value)
			assert.Empty(t, scanner.ScanString("companion-token"))
			// An ignored primary suppresses the assembled finding itself.
			scanner = mustNew(t, cfg, WithIgnoredFingerprints(
				fingerprint.Sum([]byte("primary-token")), fingerprint.Sum([]byte("companion-token")),
			))
			assert.Empty(t, scanner.ScanString("primary-token companion-token"))
		}
	}
	// Explicit global filters retain their original component filtering semantics.
	cfg := &config.Config{
		Filter: `finding["secret"] == "companion-token"`,
		Rules: []config.Rule{
			{ID: "primary", Regex: `primary-token`, Components: []config.Component{{RuleID: "component", Within: "2L"}}},
			{ID: "component", Regex: `companion-token`, SkipReport: true},
		},
	}
	assert.Empty(t, mustNew(t, cfg).ScanString("primary-token companion-token"))
}

func TestIgnoredFingerprintsSnapshotAndReuse(t *testing.T) {
	hashes := []fingerprint.Hash{fingerprint.Sum([]byte("secret-alpha"))}
	option := WithIgnoredFingerprints(hashes...)
	hashes[0] = fingerprint.Sum([]byte("secret-beta"))
	for range 2 {
		scanner := mustNew(t, testConfig(), option, option, WithIgnoredFingerprints(), WithIgnoredFingerprints(hashes...))
		for range 2 {
			findings := scanner.ScanString("secret-alpha secret-beta secret-gamma")
			require.Len(t, findings, 1)
			assert.Equal(t, "secret-gamma", findings[0].Match.Value)
		}
	}
	assert.Len(t, mustNew(t, testConfig(), WithIgnoredFingerprints()).ScanString("secret-alpha secret-beta"), 2)
	assert.Len(t, mustNew(t, testConfig()).ScanString("secret-alpha secret-beta"), 2)
}

func TestScannerLoggerIsOptIn(t *testing.T) {
	cfg := &config.Config{
		Filter: `int(finding.secret) > 0`,
		Rules: []config.Rule{{
			ID:    "test-secret",
			Regex: `secret-[a-z]+`,
		}},
	}

	silent := mustNew(t, cfg)
	assert.Equal(t, slog.DiscardHandler, silent.logger.Handler())

	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	scanner := mustNew(t, cfg, WithLogger(logger))
	require.Len(t, scanner.ScanString("secret-alpha"), 1)
	assert.Contains(t, output.String(), "global filter eval error")
}

func TestDiscardLoggerDoesNotAllocatePerRule(t *testing.T) {
	scanner := mustNew(t, testConfig())
	fragment := sources.Fragment{Raw: "ordinary input"}
	rule := &compiledRule{rule: config.Rule{ID: "test-secret", SkipReport: true}}

	var findings []report.Finding
	var scanErr error
	allocations := testing.AllocsPerRun(1_000, func() {
		findings, scanErr = scanner.detectFragmentWithRule(nil, fragment, fragment.Raw, rule, nil, nil, &detectionState{})
	})
	runtime.KeepAlive(findings)
	require.NoError(t, scanErr)
	assert.Zero(t, allocations)
}

func TestGitleaksAllowCommentSuppressesFinding(t *testing.T) {
	scanner := mustNew(t, testConfig())
	require.Empty(t, scanner.ScanString("secret-alpha // gitleaks:allow"))
}

func TestSourcePrefilter(t *testing.T) {
	cfg := testConfig()
	cfg.Prefilter = `attributes["path"] == "ignored.txt"`
	skip := mustPrefilter(t, cfg.Prefilter)
	require.NotNil(t, skip)
	assert.True(t, skip(map[string]string{sources.AttrPath: "ignored.txt"}))
	assert.False(t, skip(map[string]string{sources.AttrPath: "kept.txt"}))
}

func TestScannerRequiresConstruction(t *testing.T) {
	var output bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	for _, tc := range []struct {
		name    string
		scanner *Scanner
	}{
		{name: "nil"},
		{name: "zero value", scanner: &Scanner{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Bound the test if an uninitialized scanner waits for a worker slot.
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			summary, err := tc.scanner.Scan(ctx, fragmentSource{fragments: []sources.Fragment{{Raw: "secret-alpha"}}}, func(report.Finding) error {
				t.Error("uninitialized scanner invoked handler")
				return nil
			})
			require.EqualError(t, err, "scanner must be constructed with New")
			assert.Equal(t, ScanSummary{}, summary)
			for _, content := range []string{"", "secret-alpha"} {
				output.Reset()
				assert.Empty(t, tc.scanner.ScanString(content))
				assert.Contains(t, output.String(), `"level":"WARN"`)
				assert.Contains(t, output.String(), "scanner must be constructed with New")
			}
		})
	}
}

func TestScannerScanReturnsHandlerAndSourceErrors(t *testing.T) {
	scanner, err := New(testConfig())
	require.NoError(t, err)

	handlerErr := errors.New("store finding")
	summary, scanErr := scanner.Scan(t.Context(), fragmentSource{fragments: []sources.Fragment{{Raw: "secret-alpha"}}}, func(report.Finding) error {
		return handlerErr
	})
	assert.ErrorIs(t, scanErr, handlerErr)
	assert.Equal(t, 1, summary.Findings)

	sourceErr := errors.New("read source")
	_, scanErr = scanner.Scan(t.Context(), fragmentSource{err: sourceErr}, nil)
	assert.ErrorIs(t, scanErr, sourceErr)
}

func TestNewRejectsInvalidFindingFilters(t *testing.T) {
	for _, expression := range []string{`missingFunction()`, `finding.secret ==`, `42`} {
		for _, scope := range []string{"global", "rule", "path", "component"} {
			t.Run(scope+"/"+expression, func(t *testing.T) {
				cfg := testConfig()
				want := "compiling global filter"
				switch scope {
				case "global":
					cfg.Filter = expression
				case "rule":
					cfg.Rules[0].Filter = expression
					want = "compiling rule " + cfg.Rules[0].ID + " filter"
				case "path":
					cfg.Rules = append(cfg.Rules, config.Rule{ID: "path-only", Path: `\.env$`, Filter: expression})
					want = "compiling rule path-only filter"
				case "component":
					cfg.Rules[0].Components = []config.Component{{RuleID: "part"}}
					cfg.Rules = append(cfg.Rules, config.Rule{ID: "part", Regex: "COMPONENT", SkipReport: true, Filter: expression})
					want = "compiling rule part filter"
				}
				for _, options := range [][]Option{nil, {WithPrecompile()}} {
					scanner, err := New(cfg, options...)
					require.ErrorContains(t, err, want)
					require.Nil(t, scanner)
				}
			})
		}
	}
}

func TestFilterCompilationDoesNotInitializeTokenizer(t *testing.T) {
	cfg := testConfig()
	cfg.Filter = `tokenRatio(finding.secret) > 0`
	scanner, err := New(cfg)
	require.NoError(t, err)
	require.Nil(t, scanner.tokenCounter, "construction must compile filters without evaluating them")
}

func TestScannerDoesNotCompileProviderExpressions(t *testing.T) {
	cfg := testConfig()
	cfg.Rules[0].ValidateExpr = `missingFunction()`
	for _, options := range [][]Option{nil, {WithPrecompile()}} {
		_, err := New(cfg, options...)
		require.NoError(t, err, "scanner never compiles provider expressions")
	}
}

func TestNewValidatesOptions(t *testing.T) {
	_, err := New(nil)
	assert.Error(t, err)

	_, err = New(testConfig(), WithWorkers(-1))
	assert.ErrorContains(t, err, "workers")

	_, err = New(testConfig(), WithMatchContext("bad"))
	assert.ErrorContains(t, err, "match context")

	_, err = New(testConfig(), WithLogger(nil))
	assert.NoError(t, err)

}

func collectSourceFindings(ctx context.Context, scanner *Scanner, source sources.Source) ([]report.Finding, error) {
	var findings []report.Finding
	_, err := scanner.Scan(ctx, source, func(finding report.Finding) error {
		findings = append(findings, finding)
		return nil
	})
	return findings, err
}

func TestPathOnlyRuleRunsOnFirstFileFragment(t *testing.T) {
	rule := config.Rule{
		ID:   "path-only",
		Path: `\.p12$`,
	}
	cfg := &config.Config{
		Rules: []config.Rule{rule},
	}
	timingCollector := ruletiming.NewCollector()
	scanner := mustNew(t, cfg)
	source := &sources.File{
		Content: strings.NewReader("aa\n\nbb\n\n"),
		Path:    "bundle.p12",
		Buffer:  make([]byte, 4),
	}

	findings, err := collectSourceFindings(ruletiming.WithCollector(t.Context(), timingCollector), scanner, source)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	timings := timingCollector.Snapshot()
	require.Len(t, timings, 1)
	require.Equal(t, uint64(1), timings[0].Hits)
	require.Equal(t, "bundle.p12", findings[0].Location.Path)
}

func TestCandidateBitmap(t *testing.T) {
	rules := []config.Rule{
		{ID: "high", Specificity: 30, Keywords: []string{"shared", "alias"}, Regex: `HIGHSECRET`},
		{ID: "low", Specificity: 20, Keywords: []string{"shared"}, Regex: `LOWSECRET`},
		{ID: "cancel", Specificity: 10, Keywords: []string{"cancel"}, Regex: `ALWAYSSECRET`},
		{ID: "always", Regex: `ALWAYSSECRET`},
	}
	cfg := &config.Config{
		Rules: rules,
	}
	d := mustNew(t, cfg)
	require.Empty(t, d.ScanString("stale HIGHSECRET"))

	// Cancellation after candidates are marked must not leak them into the next scan.
	findings, err := d.detectFragmentWithState(newCancelOnSecondCheck(), sources.Fragment{Raw: "cancel ALWAYSSECRET"}, nil)
	require.NoError(t, err)
	require.Empty(t, findings)
	require.Equal(t, []string{"always"}, findingRuleIDs(d.ScanString("ALWAYSSECRET")))

	// One keyword selects multiple rules, multiple keywords select one rule,
	// rules without keywords always run, and specificity order is retained.
	require.Equal(t, []string{"high", "low", "always"}, findingRuleIDs(d.ScanString("shared HIGHSECRET LOWSECRET ALWAYSSECRET")))
	require.Equal(t, []string{"high", "always"}, findingRuleIDs(d.ScanString("alias HIGHSECRET ALWAYSSECRET")))
}

func TestNewSnapshotsConfigWithoutMutatingIt(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "low", Specificity: 10, Keywords: []string{"MiXeD"}, Regex: `LOWSECRET`},
		{ID: "high", Specificity: 20, Keywords: []string{"MiXeD"}, Regex: `HIGHSECRET`},
	}}

	d := mustNew(t, cfg)
	require.Equal(t, []string{"low", "high"}, []string{cfg.Rules[0].ID, cfg.Rules[1].ID})
	require.Equal(t, "MiXeD", cfg.Rules[0].Keywords[0])
	require.Equal(t, []string{"high", "low"}, []string{d.rulesBySpecificity[0].rule.ID, d.rulesBySpecificity[1].rule.ID})

	// Scanner behavior is isolated from later changes to the caller's config.
	cfg.Rules[0].Keywords[0] = "changed"
	cfg.Rules[0].Regex = `CHANGED`
	cfg.Rules[1] = config.Rule{ID: "replacement", Keywords: []string{"changed"}, Regex: `CHANGED`}
	cfg.Filter = "true"

	require.Equal(t, []string{"high", "low"}, findingRuleIDs(d.ScanString("mixed HIGHSECRET LOWSECRET")))
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
			if a.Match.Line != b.Match.Line {
				return a.Match.Line < b.Match.Line
			}
			if a.Match.Value != b.Match.Value {
				return a.Match.Value < b.Match.Value
			}
			if a.Match.Full != b.Match.Full {
				return a.Match.Full < b.Match.Full
			}
			return strings.Join(a.Tags, "\x00") < strings.Join(b.Tags, "\x00")
		}),
		cmpopts.IgnoreFields(report.Finding{},
			"Attributes", "ComponentSets"),
		cmpopts.IgnoreFields(report.ComponentFinding{}),
		cmpopts.EquateApprox(0.0001, 0), // For floating point Entropy comparison
	); diff != "" {
		t.Errorf("findings mismatch (-want +got):\n%s", diff)
	}
}

// stripFindingAttributes clears source metadata for match-only assertions.
// Location paths are checked separately in source handoff tests.
func stripFindingAttributes(findings []report.Finding) []report.Finding {
	for i := range findings {
		findings[i].Attributes = nil
		findings[i].Location.Path = ""
		for si := range findings[i].ComponentSets {
			for ci := range findings[i].ComponentSets[si].Components {
				findings[i].ComponentSets[si].Components[ci].Location.Path = ""
			}
		}
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
	scanner := mustNew(t, cfg)

	t.Run("required component gates finding", func(t *testing.T) {
		assert.Empty(t, scanner.ScanString("primary=secret\noptional=session"))
	})

	t.Run("absent optional component is omitted", func(t *testing.T) {
		findings := scanner.ScanString("primary=secret\nrequired=account")
		require.Len(t, findings, 1)
		require.Len(t, findings[0].ComponentSets, 1)
		require.Len(t, findings[0].ComponentSets[0].Components, 1)
		component := findings[0].ComponentSets[0].Components[0]
		assert.Equal(t, "required-component", component.RuleID)
		assert.False(t, component.Optional)
	})

	t.Run("present optional component joins combinations", func(t *testing.T) {
		findings := scanner.ScanString("primary=secret\nrequired=account\noptional=first\noptional=second")
		require.Len(t, findings, 1)
		require.Len(t, findings[0].ComponentSets, 2)
		for _, set := range findings[0].ComponentSets {
			require.Len(t, set.Components, 2)
			assert.False(t, set.Components[0].Optional)
			assert.True(t, set.Components[1].Optional)
		}
	})
}

func TestComponentPlanPreservesOrderAndOwnsConfig(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "primary", Regex: `PRIMARY`, Specificity: 20, Components: []config.Component{
			{RuleID: "required", Within: "2L"},
			{RuleID: "optional", Within: "4L", Optional: true},
		}},
		{ID: "required", Regex: `REQUIRED`, Specificity: 10, SkipReport: true},
		{ID: "optional", Regex: `OPTIONAL`, Specificity: 30, SkipReport: true},
	}}
	scanner := mustNew(t, cfg)
	require.Equal(t, "2L", cfg.Rules[0].Components[0].Within)
	require.Equal(t, "optional", cfg.Rules[0].Components[1].RuleID)
	cfg.Rules[0].Components[0] = config.Component{RuleID: "missing", Within: "invalid"}
	cfg.Rules[0].Components[1].Optional = false
	cfg.Rules[1].Regex = `CHANGED`

	// The first primary has no nearby required match; the second must survive.
	findings := scanner.ScanString("PRIMARY\n.\n.\nPRIMARY\nREQUIRED\n.\nOPTIONAL")
	require.Len(t, findings, 1)
	require.Equal(t, 4, findings[0].Location.StartLine)
	require.Len(t, findings[0].ComponentSets, 1)
	components := findings[0].ComponentSets[0].Components
	require.Len(t, components, 2)
	assert.Equal(t, "required", components[0].RuleID)
	assert.False(t, components[0].Optional)
	assert.Equal(t, "optional", components[1].RuleID)
	assert.True(t, components[1].Optional)
	require.Len(t, scanner.ScanString("PRIMARY\nREQUIRED"), 1)
}

func TestNestedComponentsRejected(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "primary", Regex: `primary=([a-z]+)`, Components: []config.Component{{RuleID: "component"}}},
		{ID: "component", Regex: `component=([a-z]+)`, Components: []config.Component{{RuleID: "nested"}}},
		{ID: "nested", Regex: `nested=([a-z]+)`},
	}}
	_, err := New(cfg)
	require.ErrorContains(t, err, "must not itself have components")
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
	scanner := mustNew(t, cfg)

	findings := scanner.ScanString("primary=secret")
	require.Len(t, findings, 1)
	assert.Empty(t, findings[0].ComponentSets)

	findings = scanner.ScanString("primary=secret\noptional=session")
	require.Len(t, findings, 1)
	require.Len(t, findings[0].ComponentSets, 1)
	require.Len(t, findings[0].ComponentSets[0].Components, 1)
	assert.True(t, findings[0].ComponentSets[0].Components[0].Optional)

	findings = scanner.ScanString("primary=shared optional=shared")
	require.Len(t, findings, 1, "a primary must not be suppressed by its own same-line, same-value component")
	require.Len(t, findings[0].ComponentSets, 1)
	assert.Equal(t, "shared", findings[0].ComponentSets[0].Components[0].Match.Value)
}

func TestGenericPasswordConfidenceAndContext(t *testing.T) {
	scanner := newDefaultTestScanner(t)

	genericPasswordFindings := func(raw string, path ...string) []report.Finding {
		t.Helper()
		detected := scanner.ScanString(raw)
		if len(path) > 0 {
			detected = scanner.detectFragment(context.Background(), sources.Fragment{
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
			assert.Equal(t, "hunter2", findings[0].Match.Value)
			assert.Equal(t, "low", findings[0].Confidence)
		})
	}

	unquotedHash := genericPasswordFindings(`password = hunter2#prod`)
	require.Len(t, unquotedHash, 1)
	assert.Equal(t, "hunter2#prod", unquotedHash[0].Match.Value)

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
	assert.Equal(t, "hunter2", rubyLiteralPassword[0].Match.Value)
	assert.Equal(t, "medium", rubyLiteralPassword[0].Confidence)
	assert.Empty(t, rubyLiteralPassword[0].ComponentSets, "a Ruby variable must not be attached as a literal username")

	quotedExpressionText := genericPasswordFindings(
		`credentials = { password: "current_user.confirm_deletion_with_password?.to_s" }`,
		"auth.rb",
	)
	require.Len(t, quotedExpressionText, 1)
	assert.Equal(t, "current_user.confirm_deletion_with_password?.to_s", quotedExpressionText[0].Match.Value)

	rubyLiterals := genericPasswordFindings(
		`credentials = { username: "alice", password: "hunter2" }`,
		"auth.rb",
	)
	require.Len(t, rubyLiterals, 1)
	require.Len(t, rubyLiterals[0].ComponentSets, 1)
	assert.Equal(t, "alice", rubyLiterals[0].ComponentSets[0].Components[0].Match.Value)

	anchoredUsernameFilter := genericPasswordFindings(
		`credentials = { username: "safe username = null, suffix", password: "hunter2" }`,
		"auth.rb",
	)
	require.Len(t, anchoredUsernameFilter, 1)
	require.Len(t, anchoredUsernameFilter[0].ComponentSets, 1)
	assert.Equal(t, "safe username = null, suffix", anchoredUsernameFilter[0].ComponentSets[0].Components[0].Match.Value)

	camelCaseClient := genericPasswordFindings(
		`credentials = { clientId: "service-client", password: "hunter2" }`,
		"auth.js",
	)
	require.Len(t, camelCaseClient, 1)
	assert.Equal(t, "medium", camelCaseClient[0].Confidence)
	require.Len(t, camelCaseClient[0].ComponentSets, 1)
	assert.Equal(t, "service-client", camelCaseClient[0].ComponentSets[0].Components[0].Match.Value)

	yamlScalars := genericPasswordFindings("credentials:\n  username: alice\n  password: hunter2", "config.yml")
	require.Len(t, yamlScalars, 1)
	require.Len(t, yamlScalars[0].ComponentSets, 1)
	assert.Equal(t, "alice", yamlScalars[0].ComponentSets[0].Components[0].Match.Value)

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
	assert.Equal(t, "alice", paired[0].ComponentSets[0].Components[0].Match.Value)

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
			assert.Equal(t, tc.secret, findings[0].Match.Value)
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
	scanner := newDefaultTestScanner(t)

	findingsForRule := func(raw, ruleID string, path ...string) []report.Finding {
		t.Helper()
		detected := scanner.ScanString(raw)
		if len(path) > 0 {
			detected = scanner.detectFragment(context.Background(), sources.Fragment{
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
			assert.Equal(t, tc.secret, finding.Match.Value)
			assert.Equal(t, "medium", finding.Confidence)
			assert.Equal(t, tc.scheme, finding.Match.Captures["scheme"])
			assert.Equal(t, tc.username, finding.Match.Captures["username"])
			assert.Equal(t, tc.secret, finding.Match.Captures["password"])
			assert.Equal(t, tc.host, finding.Match.Captures["host"])
			assert.Contains(t, finding.Match.Captures["uri"], tc.secret)
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
			assert.Equal(t, password, findings[0].Match.Value)
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
	mongodb := scanner.ScanString(`MONGO_URL="mongodb://svc-reader:q9V7nB2K4xL8@mongo.internal:27017/app"`)
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
			assert.Equal(t, tt.want, withinProximity(tt.raw, computeLineOffsets(tt.raw), tt.fragmentStartLine, tt.primary, tt.component, window))
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
	scanner := mustNew(t, cfg)

	findings := scanner.ScanString("optional=session\nprimary=secret")
	require.Len(t, findings, 1)
	require.Len(t, findings[0].ComponentSets, 1)

	findings = scanner.ScanString("primary=secret\noptional=session")
	require.Len(t, findings, 1)
	assert.Empty(t, findings[0].ComponentSets)
}

func TestDetectFilterMatchesContextWindow(t *testing.T) {
	rule := config.Rule{
		ID:     "near-match",
		Regex:  `[A-Z0-9]{20}`,
		Filter: `let matchContext = finding["fragment_raw"][max(finding["match_start_idx"] - 50, 0):finding["match_end_idx"]]; matchesAny(matchContext, ["red-herring"])`,
	}
	cfg := &config.Config{
		Rules: []config.Rule{rule},
	}

	d := mustNew(t, cfg)
	findings := d.detectFragment(context.Background(), sources.Fragment{Raw: "red-herring " + strings.Repeat("x", 55) + " ABCDEFGHIJKLMNOPQRST"})

	require.Len(t, findings, 1)
	assert.Equal(t, "ABCDEFGHIJKLMNOPQRST", findings[0].Match.Value)
}

func TestConfidenceAttributeAndFilter(t *testing.T) {
	low := config.Rule{ID: "specific-low", Regex: `[A-Z0-9]{20}`, Specificity: 1, Confidence: "low"}
	promoted := config.Rule{ID: "promoted", Regex: `[A-Z0-9]{20}`, Confidence: "medium", Filter: `let _ = setConfidence("high"); false`}
	cfg := &config.Config{
		Rules: []config.Rule{low, promoted},
	}

	scanner := mustNew(t, cfg, WithMinimumConfidence(ConfidenceHigh))
	findings := scanner.ScanString("ABCDEFGHIJKLMNOPQRST")
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
				ID:     "decoded-near-match",
				Regex:  `decoded-secret-[A-Z]{20}`,
				Filter: fmt.Sprintf(`let matchContext = finding["fragment_raw"][max(finding["match_start_idx"] - %d, 0):finding["match_end_idx"]]; containsAny(matchContext, ["provider"])`, tc.before),
			}
			cfg := &config.Config{
				Rules: []config.Rule{rule},
			}
			d := mustNew(t, cfg, WithMaxDecodeDepth(1))

			require.Len(t, d.detectFragment(context.Background(), sources.Fragment{Raw: raw}), tc.findings)
		})
	}
}

func TestFilterUsesOriginalRegexMatchBounds(t *testing.T) {
	rule := config.Rule{
		ID:     "original-match-bounds",
		Regex:  "\nSECRET",
		Filter: "let matchContext = finding[\"fragment_raw\"][finding[\"match_start_idx\"]:finding[\"match_end_idx\"]]; matchesAny(matchContext, [`\\nSECRET$`])",
	}
	cfg := &config.Config{
		Rules: []config.Rule{rule},
	}

	require.Empty(t, mustNew(t, cfg).detectFragment(context.Background(), sources.Fragment{Raw: "prefix\nSECRET"}))
}

func TestFilterContextCanStayOnMatchLine(t *testing.T) {
	rule := config.Rule{
		ID:     "line-context",
		Regex:  `SECRET`,
		Filter: `let matchContext = finding["fragment_raw"][finding["match_line_start_idx"]:finding["match_line_end_idx"]]; containsAny(matchContext, ["other-line"])`,
	}
	cfg := &config.Config{
		Rules: []config.Rule{rule},
	}

	require.Len(t, mustNew(t, cfg).detectFragment(context.Background(), sources.Fragment{Raw: "other-line\nSECRET\nother-line"}), 1)
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
				Raw: `awsToken := \"AKIALALEMEL33243OKIA\ // betterleaks:allow"`,
				Attributes: map[string]string{
					sources.AttrPath: "tmp.go",
				},
			},
		},
		"valid allow comment (2)": {
			cfgName: "simple",
			fragment: sources.Fragment{
				Raw: `awsToken := \

		        \"AKIALALEMEL33243OKIA\ // betterleaks:allow"

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

		                // betterleaks:allow"

		                `,
				Attributes: map[string]string{
					sources.AttrPath: "tmp.go",
				},
			},
			expectedFindings: []report.Finding{
				{
					Description: "AWS Access Key",
					Match:       report.Match{Value: "AKIALALEMEL33243OKIA", Full: "AKIALALEMEL33243OKIA", Line: "awsToken := \\\"AKIALALEMEL33243OKIA\\\"\n"},
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
					Match:       report.Match{Full: "AKIALALEMEL33843OLIA", Value: "AKIALALEMEL33843OLIA", Line: `awsToken := \"AKIALALEMEL33843OLIA\"`},
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
					Match:       report.Match{Full: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", Value: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", Line: `#ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij...ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`},
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
					Match:       report.Match{Full: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", Value: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", Line: `#ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij...ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`},
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
					Match:       report.Match{Full: "BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;", Value: "cafebabe:deadbeef", Line: `export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;`},
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
					Match:       report.Match{Full: "BUNDLE_ENTERPRISE__CONTRIBSYS__COM=\"cafebabe:deadbeef\"", Value: "cafebabe:deadbeef", Line: `echo hello1; export BUNDLE_ENTERPRISE__CONTRIBSYS__COM="cafebabe:deadbeef" && echo hello2`},
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
					Match:       report.Match{Full: "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:", Value: "cafeb4b3:d3adb33f", Line: `url = "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80/path?param1=true&param2=false#heading1"`},
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
					Match:       report.Match{Full: "Key = \"e8322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5\"", Value: "e8322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5", Line: `const Discord_Public_Key = "e8322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"`},
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
					Match:       report.Match{Full: "file detected: tmp.py"},
					RuleID:      "python-files-only",
					Tags:        []string{},
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
					Match: report.Match{Full: `password = "secret123"`, Value: "secret123", Line: "\t\t\tpassword = \"secret123\"\n"},
					Tags:  []string{},
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
					Match:       report.Match{Value: "-----BEGIN PRIVATE KEY-----\n135f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb\nu+QDkg0spw==\n-----END PRIVATE KEY-----", Full: "-----BEGIN PRIVATE KEY-----\n135f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb\nu+QDkg0spw==\n-----END PRIVATE KEY-----", Line: "-----BEGIN PRIVATE KEY-----\n135f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb\nu+QDkg0spw==\n-----END PRIVATE KEY-----\n"},
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
					Match:       report.Match{Value: "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCjQzNWYvYlJVQkhyYkhxTFkveFMzSTdPdGgrOHJnRyswdEJ3Zk1jYmswNVNneHE2UVV6U1lJUUFvcCtXdnNUd2syc1IrQzM4ZzBNbmIKdStRRGtnMHNwdz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K", Full: "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCjQzNWYvYlJVQkhyYkhxTFkveFMzSTdPdGgrOHJnRyswdEJ3Zk1jYmswNVNneHE2UVV6U1lJUUFvcCtXdnNUd2syc1IrQzM4ZzBNbmIKdStRRGtnMHNwdz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K", Line: "private_key: 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCjQzNWYvYlJVQkhyYkhxTFkveFMzSTdPdGgrOHJnRyswdEJ3Zk1jYmswNVNneHE2UVV6U1lJUUFvcCtXdnNUd2syc1IrQzM4ZzBNbmIKdStRRGtnMHNwdz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K'\n"},
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
					Match:       report.Match{Value: "-----BEGIN PRIVATE KEY-----\n435f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb\nu+QDkg0spw==\n-----END PRIVATE KEY-----", Full: "-----BEGIN PRIVATE KEY-----\n435f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb\nu+QDkg0spw==\n-----END PRIVATE KEY-----", Line: "private_key: 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCjQzNWYvYlJVQkhyYkhxTFkveFMzSTdPdGgrOHJnRyswdEJ3Zk1jYmswNVNneHE2UVV6U1lJUUFvcCtXdnNUd2syc1IrQzM4ZzBNbmIKdStRRGtnMHNwdz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K'\n"},
					RuleID:      "private-key",
					Tags:        []string{"key", "private"},
					Encodings:   []string{"base64"},
					DecodeDepth: 1,
					Location: report.Location{
						StartLine:   9,
						EndLine:     9,
						StartColumn: 15,
						EndColumn:   206,
					},
				},
				{ // Encoded Small secret at the end to make sure it's picked up by the decoding
					Description: "Small Secret",
					Match:       report.Match{Value: "small-secret", Full: "small-secret", Line: "c21hbGwtc2VjcmV0\n"},
					RuleID:      "small-secret",
					Tags:        []string{"small", "secret"},
					Encodings:   []string{"base64"},
					DecodeDepth: 1,
					Location: report.Location{
						StartLine:   16,
						EndLine:     16,
						StartColumn: 1,
						EndColumn:   16,
					},
				},
				{ // Secret where the decoded match goes outside the encoded value
					Description: "Overlapping",
					Match:       report.Match{Value: "decoded-secret-value00", Full: "secret=decoded-secret-value00", Line: "secret=ZGVjb2RlZC1zZWNyZXQtdmFsdWUwMA==\n"},
					RuleID:      "overlapping",
					Tags:        []string{"overlapping"},
					Encodings:   []string{"base64"},
					DecodeDepth: 1,
					Location: report.Location{
						StartLine:   19,
						EndLine:     19,
						StartColumn: 1,
						EndColumn:   39,
					},
				},
				{ // This confirms the rule is detected without a filter.
					Description: "Make sure this would be detected without a filter",
					Match:       report.Match{Value: "lRqBK-z5kf4-please-ignore-me-X-XIJM2Pddw", Full: "password=\"lRqBK-z5kf4-please-ignore-me-X-XIJM2Pddw\"", Line: "password=\"bFJxQkstejVrZjQtcGxlYXNlLWlnbm9yZS1tZS1YLVhJSk0yUGRkdw==\"\n"},
					RuleID:      "decoded-password-dont-ignore",
					Tags:        []string{"decode-ignore"},
					Encodings:   []string{"base64"},
					DecodeDepth: 1,
					Location: report.Location{
						StartLine:   24,
						EndLine:     24,
						StartColumn: 1,
						EndColumn:   67,
					},
				},
				{ // Hex encoded data check
					Description: "Overlapping",
					Match:       report.Match{Value: "decoded-secret-valuevHEX", Full: "secret=decoded-secret-valuevHEX", Line: "secret=6465636F6465642D7365637265742D76616C756576484558\n"},
					RuleID:      "overlapping",
					Tags:        []string{"overlapping"},
					Encodings:   []string{"hex"},
					DecodeDepth: 1,
					Location: report.Location{
						StartLine:   27,
						EndLine:     27,
						StartColumn: 1,
						EndColumn:   55,
					},
				},
				{ // handle partial encoded percent data
					Description: "Overlapping",
					Match:       report.Match{Value: "decoded-secret-valuev2", Full: "secret=decoded-secret-valuev2", Line: "secret=decoded-%73%65%63%72%65%74-valuev2\n"},
					RuleID:      "overlapping",
					Tags:        []string{"overlapping"},
					Encodings:   []string{"percent"},
					DecodeDepth: 1,
					Location: report.Location{
						StartLine:   31,
						EndLine:     31,
						StartColumn: 1,
						EndColumn:   41,
					},
				},
				{ // handle partial encoded percent data
					Description: "Overlapping",
					Match:       report.Match{Value: "decoded-secret-valuev3", Full: "secret=decoded-secret-valuev3", Line: "secret=%64%65coded-%73%65%63%72%65%74-valuev3\n"},
					RuleID:      "overlapping",
					Tags:        []string{"overlapping"},
					Encodings:   []string{"percent"},
					DecodeDepth: 1,
					Location: report.Location{
						StartLine:   33,
						EndLine:     33,
						StartColumn: 1,
						EndColumn:   45,
					},
				},
				{ // Encoded AWS config with a access key id inside a JWT
					Description: "AWS IAM Unique Identifier",
					Match:       report.Match{Value: "ASIAIOSFODNN7LXM10JI", Full: " ASIAIOSFODNN7LXM10JI", Line: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiY29uZmlnIjoiVzJSbFptRjFiSFJkQ25KbFoybHZiaUE5SUhWekxXVmhjM1F0TWdwaGQzTmZZV05qWlhOelgydGxlVjlwWkNBOUlFRlRTVUZKVDFOR1QwUk9UamRNV0UweE1FcEpDbUYzYzE5elpXTnlaWFJmWVdOalpYTnpYMnRsZVNBOUlIZEtZV3h5V0ZWMGJrWkZUVWt2U3pkTlJFVk9SeTlpVUhoU1ptbERXVVZHVlVORWJFVllNVUVLIiwiaWF0IjoxNTE2MjM5MDIyfQ.8gxviXEOuIBQk2LvTYHSf-wXVhnEKC3h4yM5nlOF4zA\n"},
					RuleID:      "aws-iam-unique-identifier",
					Tags:        []string{"aws", "identifier"},
					Encodings:   []string{"base64"},
					DecodeDepth: 2,
					Location: report.Location{
						StartLine:   12,
						EndLine:     12,
						StartColumn: 38,
						EndColumn:   343,
					},
				},
				{ // Encoded AWS config with a secret access key inside a JWT
					Description: "AWS Secret Access Key",
					Match:       report.Match{Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEFUCDlEX1A", Full: "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEFUCDlEX1A", Line: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiY29uZmlnIjoiVzJSbFptRjFiSFJkQ25KbFoybHZiaUE5SUhWekxXVmhjM1F0TWdwaGQzTmZZV05qWlhOelgydGxlVjlwWkNBOUlFRlRTVUZKVDFOR1QwUk9UamRNV0UweE1FcEpDbUYzYzE5elpXTnlaWFJmWVdOalpYTnpYMnRsZVNBOUlIZEtZV3h5V0ZWMGJrWkZUVWt2U3pkTlJFVk9SeTlpVUhoU1ptbERXVVZHVlVORWJFVllNVUVLIiwiaWF0IjoxNTE2MjM5MDIyfQ.8gxviXEOuIBQk2LvTYHSf-wXVhnEKC3h4yM5nlOF4zA\n"},
					RuleID:      "aws-secret-access-key",
					Tags:        []string{"aws", "secret"},
					Encodings:   []string{"base64"},
					DecodeDepth: 2,
					Location: report.Location{
						StartLine:   12,
						EndLine:     12,
						StartColumn: 38,
						EndColumn:   343,
					},
				},
				{ // Secret where the decoded match goes outside the encoded value and then encoded again
					Description: "Overlapping",
					Match:       report.Match{Value: "decoded-secret-value", Full: "secret=decoded-secret-value", Line: "c2VjcmV0PVpHVmpiMlJsWkMxelpXTnlaWFF0ZG1Gc2RXVT0=\n"},
					RuleID:      "overlapping",
					Tags:        []string{"overlapping"},
					Encodings:   []string{"base64"},
					DecodeDepth: 2,
					Location: report.Location{
						StartLine:   21,
						EndLine:     21,
						StartColumn: 1,
						EndColumn:   48,
					},
				},
				{ // handle encodings that touch eachother
					Description: "Overlapping",
					Match:       report.Match{Value: "decoded-secret-valuev5", Full: "secret=decoded-secret-valuev5", Line: "secret%3d6465636F6465642D7365637265742D76616C75657635\n"},
					RuleID:      "overlapping",
					Tags:        []string{"overlapping"},
					Encodings:   []string{"percent", "hex"},
					DecodeDepth: 2,
					Location: report.Location{
						StartLine:   41,
						EndLine:     41,
						StartColumn: 1,
						EndColumn:   53,
					},
				},
				{ // handle partial encoded percent data465642D7365637265742D76616C75657635
					Description: "Overlapping",
					Match:       report.Match{Value: "decoded-secret-valuev4", Full: "secret=decoded-secret-valuev4", Line: "c2VjcmV0PVpHVmpiMl%4AsWkMxelpXTnlaWFF0ZG1Gc2RXVjJOQT09\n"},
					RuleID:      "overlapping",
					Tags:        []string{"overlapping"},
					Encodings:   []string{"percent", "base64"},
					DecodeDepth: 3,
					Location: report.Location{
						StartLine:   39,
						EndLine:     39,
						StartColumn: 1,
						EndColumn:   54,
					},
				},
				{ // multiple percent encodings in a single layer base64
					Description: "Overlapping",
					Match:       report.Match{Value: "decoded-secret-valuex86", Full: "secret=decoded-secret-valuex86", Line: "secret=ZGVjb2%52lZC1zZWNyZXQtdm%46sdWV4ODY=  # ends in x86\n"},
					RuleID:      "overlapping",
					Tags:        []string{"overlapping"},
					Encodings:   []string{"percent", "base64"},
					DecodeDepth: 2,
					Location: report.Location{
						StartLine:   43,
						EndLine:     43,
						StartColumn: 1,
						EndColumn:   43,
					},
				},
				{ // base64 encoded partially percent encoded value
					Description: "Overlapping",
					Match:       report.Match{Value: "decoded-secret-value", Full: "secret=decoded-secret-value", Line: "secret=ZGVjb2RlZC0lNzMlNjUlNjMlNzIlNjUlNzQtdmFsdWU=\n"},
					RuleID:      "overlapping",
					Tags:        []string{"overlapping"},
					Encodings:   []string{"percent", "base64"},
					DecodeDepth: 2,
					Location: report.Location{
						StartLine:   45,
						EndLine:     45,
						StartColumn: 1,
						EndColumn:   51,
					},
				},
				{ // one of the lines above that went through... a lot
					Description: "Overlapping",
					Match:       report.Match{Value: "decoded-secret-value", Full: "secret=decoded-secret-value", Line: "Look at this value: %4EjMzMjU2NkE2MzZENTYzMDUwNTY3MDQ4%4eTY2RDcwNjk0RDY5NTUzMTRENkQ3ODYx%25%34%65TE3QTQ2MzY1NzZDNjQ0RjY1NTY3MDU5NTU1ODUyNkI2MjUzNTUzMDRFNkU0RTZCNTYzMTU1MzkwQQ== # isn't it crazy?\n"},
					RuleID:      "overlapping",
					Tags:        []string{"overlapping"},
					Encodings:   []string{"percent", "hex", "base64"},
					DecodeDepth: 7,
					Location: report.Location{
						StartLine:   48,
						EndLine:     48,
						StartColumn: 21,
						EndColumn:   176,
					},
				},
				{ // Multi percent encode two random characters close to the bounds of the base64
					Description: "Overlapping",
					Match:       report.Match{Value: "decoded-secret-value", Full: "secret=decoded-secret-value", Line: "secret=ZG%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%36%25%33%31%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%33%25%33%322RlZC1zZWNyZXQtd%25%36%64%25%34%36%25%37%33dWU=\n"},
					RuleID:      "overlapping",
					Tags:        []string{"overlapping"},
					Encodings:   []string{"percent", "base64"},
					DecodeDepth: 5,
					Location: report.Location{
						StartLine:   51,
						EndLine:     51,
						StartColumn: 1,
						EndColumn:   299,
					},
				},
				{ // The similar to the above but also touching the edge of the base64
					Description: "Overlapping",
					Match:       report.Match{Value: "decoded-secret-value", Full: "secret=decoded-secret-value", Line: "secret=%25%35%61%25%34%37%25%35%36jb2RlZC1zZWNyZXQtdmFsdWU%25%32%35%25%33%33%25%36%34\n"},
					RuleID:      "overlapping",
					Tags:        []string{"overlapping"},
					Encodings:   []string{"percent", "base64"},
					DecodeDepth: 4,
					Location: report.Location{
						StartLine:   53,
						EndLine:     53,
						StartColumn: 1,
						EndColumn:   85,
					},
				},
				{ // The similar to the above but also touching and overlapping the base64
					Description: "Overlapping",
					Match:       report.Match{Value: "decoded-secret-value", Full: "secret=decoded-secret-value", Line: "secret%3D%25%35%61%25%34%37%25%35%36jb2RlZC1zZWNyZXQtdmFsdWU%25%32%35%25%33%33%25%36%34\n"},
					RuleID:      "overlapping",
					Tags:        []string{"overlapping"},
					Encodings:   []string{"percent", "base64"},
					DecodeDepth: 4,
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
			d := mustNew(t, cfg, WithMaxDecodeDepth(maxDecodeDepth))
			findings := d.detectFragment(context.Background(), tt.fragment)

			compare(t, findings, tt.expectedFindings)

			if tt.expectedAuxOutput != "" {
				var output strings.Builder
				for _, finding := range findings {
					var pretty strings.Builder
					require.NoError(t, report.WritePretty(&pretty, finding, report.PrettyOptions{NoColor: true}))
					_, components, ok := strings.Cut(pretty.String(), "│ components:")
					if ok {
						components, _, _ = strings.Cut(components, "└○")
						output.WriteString("│ components:" + components)
					}
				}
				assert.Equal(t, stripANSI(tt.expectedAuxOutput), output.String())
			}

		})
	}
}

func stripANSI(s string) string {
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return ansiRegex.ReplaceAllString(s, "")
}

func expectedAWSFinding(line string, location report.Location) report.Finding {
	return report.Finding{
		RuleID:      "aws-access-key",
		Description: "AWS Access Key",
		Location:    location,
		Match:       report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: line},
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
					Match: report.Match{Value: "AKIALALEMEL33243OLIA", Full: "AKIALALEMEL33243OLIA", Line: "    awsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Value: "AKIALALEMEL33243OLIA", Full: "AKIALALEMEL33243OLIA", Line: "\taws_token := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Value: "AKIALALEMEL33243OLIA", Full: "AKIALALEMEL33243OLIA", Line: "\taws_token := \"AKIALALEMEL33243OLIA\"\n"},

					Tags: []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
				},
			},
		},
	}

	moveDotGit(t, "dotGit", ".git")
	defer moveDotGit(t, ".git", "dotGit")

	for _, tt := range tests {
		t.Run(strings.Join([]string{tt.cfgName, tt.source, tt.logOpts}, "/"), func(t *testing.T) {
			cfg := loadTestConfig(t, "simple")
			scanner := mustNew(t, cfg)

			platform, remoteURL := sources.ResolveRemote(t.Context(), scm.UnknownPlatform, tt.source)
			findings, err := collectSourceFindings(
				t.Context(), scanner,

				&sources.Git{
					RepoPath:        tt.source,
					LogOpts:         tt.logOpts,
					Workers:         1,
					ShouldSkip:      mustPrefilter(t, cfg.Prefilter),
					Platform:        platform,
					RemoteURL:       remoteURL,
					MaxArchiveDepth: 8,
				})

			require.NoError(t, err)

			for _, f := range findings {
				f.Match.Full = "" // remove lines cause copying and pasting them has some wack formatting
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\taws_token2 := \"AKIALALEMEL33243OLIA\" // this one is not\n"},
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
		scanner := mustNew(t, cfg)
		platform, remoteURL := sources.ResolveRemote(t.Context(), scm.UnknownPlatform, tt.source)
		findings, err := collectSourceFindings(
			t.Context(), scanner,

			&sources.Git{
				RepoPath:   tt.source,
				Mode:       sources.GitStaged,
				ShouldSkip: mustPrefilter(t, cfg.Prefilter),
				Platform:   platform,
				RemoteURL:  remoteURL,
			})

		require.NoError(t, err)

		for _, f := range findings {
			f.Match.Full = "" // remove lines cause copying and pasting them has some wack formatting
		}
		assert.ElementsMatch(t, stripFindingAttributes(tt.expectedFindings), stripFindingAttributes(findings))
	}
}

func TestScanBinaryFiles(t *testing.T) {
	cfg, err := config.Default()
	require.NoError(t, err)
	dir := t.TempDir()
	const token = "ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5" // betterleaks:allow
	files := map[string]string{
		"program":     "\x7fELF\x02\x01\x01\x00",
		"program.exe": "MZ\x90\x00",
		"report.pdf":  "%PDF-1.4\n",
		"image.png":   "\x89PNG\r\n\x1a\n",
		"font.woff":   "wOFF\x00\x01\x00\x00",
		"data.bin":    "\x00\xff\xfe\x80",
	}
	for name, header := range files {
		content := header + strings.Repeat("\x00", 256) + "\nGITHUB_TOKEN=" + token + "\n\xff\x00"
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	for _, engine := range []regexp.Engine{regexp.Stdlib{}, re2.RE2{}} {
		t.Run(engine.Version(), func(t *testing.T) {
			for _, usePrefilter := range []bool{true, false} {
				t.Run(fmt.Sprintf("prefilter=%t", usePrefilter), func(t *testing.T) {
					source := &sources.Files{Path: dir}
					want := []string{"program", "program.exe", "report.pdf", "data.bin"}
					if usePrefilter {
						source.ShouldSkip = mustPrefilter(t, cfg.Prefilter)
					} else {
						want = []string{"program", "program.exe", "report.pdf", "image.png", "font.woff", "data.bin"}
					}
					scanner := mustNew(t, cfg, WithRegexEngine(engine))
					findings, err := collectSourceFindings(t.Context(), scanner, source)
					require.NoError(t, err)
					var seen []string
					for _, finding := range findings {
						assert.Equal(t, "github-pat", finding.RuleID)
						assert.Equal(t, token, finding.Match.Value)
						seen = append(seen, filepath.Base(finding.Location.Path))
					}
					assert.ElementsMatch(t, want, seen)
				})
			}
		})
	}
}

func TestScanTGZArchives(t *testing.T) {
	const secret = "secret-token-EXAMPLE"
	archive := func(name string, content []byte) []byte {
		var output bytes.Buffer
		gz := gzip.NewWriter(&output)
		tw := tar.NewWriter(gz)
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content))}))
		_, err := tw.Write(content)
		require.NoError(t, err)
		require.NoError(t, tw.Close())
		require.NoError(t, gz.Close())
		return output.Bytes()
	}
	payload := archive("secret.txt", []byte(secret+"\n"))
	scanner := mustNew(t, &config.Config{Rules: []config.Rule{{ID: "token", Regex: `secret-token-[A-Z]+`}}})
	for _, tc := range []struct {
		name  string
		data  []byte
		inner string
		depth int
	}{
		{"fixture.tar.gz", payload, "secret.txt", 1},
		{"fixture.tgz", payload, "secret.txt", 1},
		{"fixture.TGZ", payload, "secret.txt", 1},
		{"outer.tar.gz", archive("nested.tgz", payload), "nested.tgz!secret.txt", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.name)
			require.NoError(t, os.WriteFile(path, tc.data, 0o600))
			for depth := 0; depth <= tc.depth; depth++ {
				findings, err := collectSourceFindings(t.Context(), scanner, &sources.Files{Path: path, MaxArchiveDepth: depth})
				require.NoError(t, err)
				if depth < tc.depth {
					require.Empty(t, findings, "archive depth %d", depth)
					continue
				}
				require.Len(t, findings, 1)
				assert.Equal(t, secret, findings[0].Match.Value)
				assert.Equal(t, filepath.ToSlash(path)+"!"+tc.inner, findings[0].Location.Path)
				assert.Equal(t, 1, findings[0].Location.StartLine)
			}
		})
	}
}

func TestBinaryFindingReports(t *testing.T) {
	const token = "token-abc123XYZ"
	cfg := &config.Config{Rules: []config.Rule{{ID: "token", Regex: `token-[a-zA-Z0-9]+`}}}
	for _, engine := range []regexp.Engine{regexp.Stdlib{}, re2.RE2{}} {
		for _, decoded := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/decoded=%t", engine.Version(), decoded), func(t *testing.T) {
				payload := token
				if decoded {
					payload = base64.StdEncoding.EncodeToString([]byte(token))
				}
				prefix := "SQLite format 3\x00\xff\x1b[2J" + strings.Repeat("\x00", 256)
				raw := prefix + `"` + payload + `"` + "\x00\xfe"
				path := filepath.Join(t.TempDir(), "data.db")
				require.NoError(t, os.WriteFile(path, []byte(raw), 0o600))
				scanner := mustNew(t, cfg, WithRegexEngine(engine), WithMaxDecodeDepth(1))
				findings, err := collectSourceFindings(t.Context(), scanner, &sources.Files{Path: path})
				require.NoError(t, err)
				require.Len(t, findings, 1)
				f := findings[0]
				assert.Empty(t, f.Tags, "decoding metadata must not become rule tags")
				if decoded {
					assert.Equal(t, []string{"base64"}, f.Encodings)
					assert.Equal(t, 1, f.DecodeDepth)
				} else {
					assert.Empty(t, f.Encodings)
					assert.Zero(t, f.DecodeDepth)
				}
				require.Equal(t, token, f.Match.Value)
				require.Equal(t, token, f.Match.Full)
				assert.Equal(t, payload, raw[f.Location.StartColumn-1:f.Location.EndColumn])
				var pretty bytes.Buffer
				require.NoError(t, report.WritePretty(&pretty, f, report.PrettyOptions{NoColor: true}))
				assert.Contains(t, pretty.String(), token)
				assert.Contains(t, pretty.String(), strings.Repeat("^", len(token)))
				assert.NotContains(t, pretty.String(), "decoded value:")
				for _, jsonl := range []bool{false, true} {
					var output bytes.Buffer
					var got []report.Finding
					if jsonl {
						require.NoError(t, report.WriteJSONL(&output, findings))
						got = make([]report.Finding, 1)
						require.NoError(t, json.Unmarshal(output.Bytes(), &got[0]))
					} else {
						require.NoError(t, report.WriteJSON(&output, findings))
						require.NoError(t, json.Unmarshal(output.Bytes(), &got))
					}
					require.Len(t, got, 1)
					assert.Equal(t, f.Match.Value, got[0].Match.Value)
					assert.Equal(t, f.Match.Full, got[0].Match.Full)
					assert.Equal(t, f.Location, got[0].Location)
					assert.Equal(t, f.Tags, got[0].Tags)
					assert.Equal(t, f.Encodings, got[0].Encodings)
					assert.Equal(t, f.DecodeDepth, got[0].DecodeDepth)
				}
			})
		}
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "PASSWORD=8ae31cacf141669ddfb5da", Value: "8ae31cacf141669ddfb5da", Line: "DB_PASSWORD=8ae31cacf141669ddfb5da\n"},
					Tags:  []string{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.cfgName+" - "+tt.source, func(t *testing.T) {
			cfg := loadTestConfig(t, tt.cfgName)
			scanner := mustNew(t, cfg)

			findings, err := collectSourceFindings(
				t.Context(), scanner,

				&sources.Files{
					ShouldSkip:     mustPrefilter(t, cfg.Prefilter),
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
		expectedError    error
		expectedFindings []report.Finding
	}{
		{
			source:           filepath.Join(archivesBasePath, "this-path-does-not-exist"),
			cfgName:          "archives",
			expectedError:    os.ErrNotExist,
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
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
					Match: report.Match{Full: "AKIALALEMEL33243OLIA", Value: "AKIALALEMEL33243OLIA", Line: "\tawsToken := \"AKIALALEMEL33243OLIA\"\n"},
					Tags:  []string{"key", "AWS"},
				},
			},
		},
		{
			source:           filepath.Join(archivesBasePath, "nested.tar.gz"),
			cfgName:          "archives",
			expireContext:    true,
			expectedError:    context.Canceled,
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
			scanner := mustNew(t, cfg)
			findings, err := collectSourceFindings(
				ctx, scanner,
				&sources.Files{
					Path:            tt.source,
					ShouldSkip:      mustPrefilter(t, cfg.Prefilter),
					MaxArchiveDepth: 8,
				})

			if tt.expectedError != nil {
				require.ErrorIs(t, err, tt.expectedError)
			} else {
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
					Match: report.Match{Full: "-----BEGIN OPENSSH PRIVATE KEY-----", Value: "-----BEGIN OPENSSH PRIVATE KEY-----", Line: "-----BEGIN OPENSSH PRIVATE KEY-----\n"},
					Tags:  []string{"key", "AsymmetricPrivateKey"},
				},
			},
		},
	}

	for _, tt := range tests {
		cfg := loadTestConfig(t, "simple")
		scanner := mustNew(t, cfg)
		findings, err := collectSourceFindings(
			t.Context(), scanner,

			&sources.Files{
				ShouldSkip:     mustPrefilter(t, cfg.Prefilter),
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
		ID:   "test-rule",
		Path: `(^|/)\.m2/settings\.xml`,
	}
	windowsRule := config.Rule{
		ID:   "test-rule",
		Path: `(^|\\)\.m2\\settings\.xml`,
	}
	expected := []report.Finding{
		{
			RuleID: "test-rule",
			Match:  report.Match{Full: "file detected: .m2/settings.xml"},
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
				ID:    "test-rule",
				Regex: `<password>(.+?)</password>`,
				Path:  `(^|/)\.m2/settings\.xml`,
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
					Match: report.Match{Full: "<password>s3cr3t</password>", Value: "s3cr3t", Line: "<password>s3cr3t</password>"},
					Tags:  []string{},
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
				ID:    "test-rule",
				Regex: `<password>(.+?)</password>`,
				Path:  `(^|\\)\.m2\\settings\.xml`,
			},
			// Paths are normalized to use Unix separators before detection.
			expected: nil,
		},
	}

	d := newDefaultTestScanner(t)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			rules, _, err := snapshotRules(&config.Config{Rules: []config.Rule{test.rule}}, nil)
			require.NoError(t, err)
			actual, err := d.detectFragmentWithRule(nil, test.fragment, test.fragment.Raw, &rules[0], []*codec.EncodedSegment{}, nil, &detectionState{})
			require.NoError(t, err)
			compare(t, actual, test.expected)
		})
	}
}

func TestCapturesUseOriginalMatch(t *testing.T) {
	for _, engine := range []regexp.Engine{regexp.Stdlib{}, re2.RE2{}} {
		t.Run(engine.Version(), func(t *testing.T) {
			t.Parallel()
			for _, tc := range []struct {
				name, pattern, input, full, value string
				secretGroup                       int
				captures                          map[string]string
			}{
				{name: "start anchor", pattern: `^(?P<start>secret)|(?P<later>secret)`, input: "xsecret", full: "secret", value: "secret", captures: map[string]string{"later": "secret"}},
				{name: "end anchor", pattern: `(?P<end>secret)$|(?P<before>secret)`, input: "secretx", full: "secret", value: "secret", captures: map[string]string{"before": "secret"}},
				{name: "word boundary", pattern: `\b(?P<word>secret)|(?P<inside>secret)`, input: "xsecret", full: "secret", value: "secret", captures: map[string]string{"inside": "secret"}},
				{name: "explicit group", pattern: `^(?P<start>a)b|a(?P<later>b)`, input: "xab", secretGroup: 2, full: "ab", value: "b", captures: map[string]string{"later": "b"}},
				{name: "unmatched group", pattern: `(?P<optional>missing)?(?P<token>secret)`, input: "secret", secretGroup: 1, full: "secret", value: "", captures: map[string]string{"token": "secret"}},
				{name: "first participating group", pattern: `(missing)?(?P<token>secret)`, input: "secret", full: "secret", value: "secret", captures: map[string]string{"token": "secret"}},
				{name: "empty group", pattern: `(?P<empty>)(?P<token>secret)`, input: "secret", full: "secret", value: "secret", captures: map[string]string{"token": "secret"}},
				{name: "trimmed newline", pattern: `(?P<token>secret)\n`, input: "secret\n", full: "secret", value: "secret", captures: map[string]string{"token": "secret"}},
				{name: "newline in capture", pattern: `(?P<token>secret\n)`, input: "secret\n", full: "secret", value: "secret\n", captures: map[string]string{"token": "secret\n"}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					scanner := mustNew(t, &config.Config{Rules: []config.Rule{{ID: "token", Regex: tc.pattern, SecretGroup: tc.secretGroup}}}, WithRegexEngine(engine))
					findings := scanner.ScanString(tc.input)
					require.Len(t, findings, 1)
					assert.Equal(t, tc.full, findings[0].Match.Full)
					assert.Equal(t, tc.value, findings[0].Match.Value)
					assert.Equal(t, tc.captures, findings[0].Match.Captures)
				})
			}

			t.Run("decoded offsets and filter bindings", func(t *testing.T) {
				scanner := mustNew(t, &config.Config{Rules: []config.Rule{{
					ID: "token", Regex: `^(?P<start>secret)|(?P<later>secret)`,
					Filter: `finding.captures.later != "secret" || finding.match_start_idx != 1 || finding.match_end_idx != 7`,
				}}}, WithMaxDecodeDepth(2))
				encoded := base64.StdEncoding.EncodeToString([]byte("xsecret padding-1234567890"))
				encoded = base64.StdEncoding.EncodeToString([]byte(encoded))
				findings := scanner.detectFragment(t.Context(), sources.Fragment{Raw: encoded, StartLine: 9})
				require.Len(t, findings, 1)
				assert.Equal(t, map[string]string{"later": "secret"}, findings[0].Match.Captures)
				assert.Equal(t, report.Location{StartLine: 9, EndLine: 9, StartColumn: 1, EndColumn: len(encoded)}, findings[0].Location)
			})
		})
	}
}

func TestFiltersReceiveNamedCaptures(t *testing.T) {
	for _, scope := range []string{"global", "rule"} {
		t.Run(scope, func(t *testing.T) {
			cfg := &config.Config{Rules: []config.Rule{{
				ID: "connection", Regex: `(?P<username>[a-z]+):(?P<password>key-[a-z]+)`, SecretGroup: 2,
			}}}
			filter := `finding.captures["username"] == "example" && finding.secret == "key-fixture"`
			if scope == "global" {
				cfg.Filter = filter
			} else {
				cfg.Rules[0].Filter = filter
			}
			d := mustNew(t, cfg, WithPrecompile())
			findings := d.ScanString("example:key-fixture alice:key-live")
			require.Len(t, findings, 1)
			require.Equal(t, "key-live", findings[0].Match.Value)
			require.Equal(t, "alice", findings[0].Match.Captures["username"])
		})
	}

	for _, pattern := range []string{`key`, `(?P<optional>prefix)?key`} {
		cfg := &config.Config{Rules: []config.Rule{{ID: "empty", Regex: pattern,
			Filter: `len(finding.captures) == 0 && (finding.captures?.missing ?? "fallback") == "fallback"`,
		}}}
		require.Empty(t, mustNew(t, cfg, WithPrecompile()).ScanString("key"))
	}
}

func TestScannerNeverExecutesProviderPrograms(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	cfg := testConfig()
	cfg.Rules[0].ValidateExpr = fmt.Sprintf(`let r = http.get(%q, {}); {"result":"valid"}`, server.URL)
	cfg.Rules[0].AnalyzeExpr = `this is not a valid program ???`
	scanner := mustNew(t, cfg, WithPrecompile())
	findings := scanner.ScanString("secret-alpha")
	require.Len(t, findings, 1)
	require.True(t, findings[0].Analysis.IsZero())
	_, err := scanner.Scan(t.Context(), &sources.Reader{Content: strings.NewReader("secret-alpha")}, nil)
	require.NoError(t, err)
	require.Zero(t, requests.Load())
	// Local filter bindings cannot use provider HTTP or environment access.
	for _, filter := range []string{`http.get("https://example.invalid", {}).status == 200`, `env.get("TOKEN") == "skip"`} {
		cfg.Filter = filter
		_, err := New(cfg, WithPrecompile())
		require.Error(t, err)
	}
}

func TestScannerConcurrentReuse(t *testing.T) {
	cfg := testConfig()
	cfg.Filter = `finding.secret == "secret-ignored"`
	scanner := mustNew(t, cfg, WithWorkers(2))
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			const content = "secret-alpha secret-ignored"
			summary, err := scanner.Scan(t.Context(), &sources.Reader{Content: strings.NewReader(content)}, func(f report.Finding) error {
				if f.Match.Value != "secret-alpha" {
					return fmt.Errorf("unexpected finding: %s", f.RuleID)
				}
				return nil
			})
			if err != nil || summary.Findings != 1 || summary.BytesInspected != uint64(len(content)) {
				t.Errorf("scan failed: summary=%+v err=%v", summary, err)
			}
		})
	}
	wg.Wait()
}

func TestScannerHandlerMayStartIndependentScan(t *testing.T) {
	scanner := mustNew(t, testConfig(), WithWorkers(1))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	source := &countedFragmentSource{count: 100}
	summary, err := scanner.Scan(ctx, source, func(report.Finding) error {
		_, err := scanner.Scan(ctx, &sources.Reader{Content: strings.NewReader("secret-beta")}, nil)
		return err
	})
	require.NoError(t, err)
	require.Equal(t, source.count*3, summary.Findings)
}

func TestFindingMatchAndLocationHandoff(t *testing.T) {
	cfg := testConfig()
	cfg.Rules[0].Regex = `token=(?P<token>[a-z]+)`
	cfg.Rules[0].Keywords = nil
	cfg.Rules[0].Filter = `let _ = setConfidence("high"); attributes.path != "archive.zip!service.env"`
	scanner := mustNew(t, cfg, WithPrecompile())
	attrs := map[string]string{sources.AttrPath: "archive.zip!service.env", sources.AttrResource: sources.ResourceFileContent}
	var finding report.Finding
	summary, err := scanner.Scan(t.Context(), &sources.Reader{Content: strings.NewReader("token=alpha"), Attributes: attrs}, func(f report.Finding) error { finding = f; return nil })
	require.NoError(t, err)
	require.Equal(t, 1, summary.Findings)
	require.Equal(t, report.Match{Full: "token=alpha", Value: "alpha", Captures: map[string]string{"token": "alpha"}, Line: "token=alpha"}, finding.Match)
	require.Equal(t, "archive.zip!service.env", finding.Location.Path)
	require.Equal(t, 1, finding.Location.StartLine)
	require.Equal(t, "high", finding.Confidence)
	require.Equal(t, map[string]string{sources.AttrResource: sources.ResourceFileContent}, finding.Attributes)
	require.Equal(t, "archive.zip!service.env", attrs[sources.AttrPath], "source attributes must remain intact")
	require.True(t, finding.Analysis.IsZero())
}

func TestContextRetentionIsExplicit(t *testing.T) {
	const content = "tenant=acme\nsecret-alpha\nmode=dev"
	for _, tc := range []struct{ name, window, want string }{
		{name: "default"},
		{name: "match line", window: "1L", want: "secret-alpha"},
		{name: "surrounding lines", window: "2L", want: content},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Rules[0].ValidateExpr = `{"result":"valid", "metadata": {"evidence":finding.context}}`
			cfg.Rules[0].AnalyzeExpr = `{"reason":finding.context}`
			// Local context extraction needs no retained copy. The optional context
			// binding must reflect exactly the window the caller requested.
			cfg.Rules[0].Filter = fmt.Sprintf(`finding.line != "secret-alpha\n" || finding.context != %q || !(finding.fragment_raw[max(finding.match_start_idx - 20, 0):finding.match_start_idx] contains "tenant=acme")`, tc.want)
			options := []Option{WithPrecompile()}
			if tc.window != "" {
				options = append(options, WithMatchContext(tc.window))
			}
			scanner := mustNew(t, cfg, options...)
			findings := scanner.ScanString(content)
			require.Len(t, findings, 1)
			require.Equal(t, "secret-alpha\n", findings[0].Match.Line)
			require.Equal(t, tc.want, findings[0].Match.Context)
			require.Equal(t, tc.want, exprFinding(findings[0])["context"])
			require.True(t, findings[0].Analysis.IsZero())
		})
	}
}

func TestComponentMatchesRetainSourceText(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "token", Regex: `token-[a-z]+`, Components: []config.Component{{RuleID: "tenant", Within: "1L"}}},
		{ID: "tenant", Regex: `tenant-[a-z]+`, SkipReport: true},
	}}
	scanner := mustNew(t, cfg, WithMatchContext("1L"))
	findings := scanner.ScanString("before\ntenant-acme token-alpha\nafter")
	require.Len(t, findings, 1)
	finding := findings[0]
	require.Len(t, finding.ComponentSets, 1)
	require.Len(t, finding.ComponentSets[0].Components, 1)
	component := finding.ComponentSets[0].Components[0]
	require.Equal(t, "tenant-acme", component.Match.Value)
	for _, match := range []report.Match{finding.Match, component.Match} {
		require.Equal(t, "tenant-acme token-alpha\n", match.Line)
		require.Equal(t, "tenant-acme token-alpha", match.Context)
	}
}

func TestConfigPathDoesNotControlSDKScanning(t *testing.T) {
	cfg := &config.Config{Path: "rules.toml", Rules: []config.Rule{{ID: "token", Regex: `TOKEN`}}}
	for _, exclude := range []bool{false, true} {
		var skip sources.SkipFunc
		if exclude {
			var err error
			skip, err = prefilter.Compile("", prefilter.Options{ExcludedPaths: []string{"rules.toml"}})
			require.NoError(t, err)
		}
		scanner, err := New(cfg)
		require.NoError(t, err)
		count := 0
		_, err = scanner.Scan(t.Context(), &sources.Reader{Content: strings.NewReader("TOKEN"), Attributes: map[string]string{sources.AttrPath: "rules.toml"}, ShouldSkip: skip}, func(f report.Finding) error { count++; return nil })
		require.NoError(t, err)
		if exclude {
			require.Zero(t, count)
		} else {
			require.Equal(t, 1, count)
		}
	}
}

func TestPathOnlyFindingsHonorFilters(t *testing.T) {
	for _, global := range []bool{false, true} {
		cfg := &config.Config{Rules: []config.Rule{{ID: "path", Path: `\.env$`}}}
		expression := `attributes.path == "skip.env" && finding.fragment_raw == "" && finding.match_start_idx == 0`
		if global {
			cfg.Filter = expression
		} else {
			cfg.Rules[0].Filter = expression
		}
		scanner, err := New(cfg, WithPrecompile())
		require.NoError(t, err)
		for _, path := range []string{"skip.env", "keep.env"} {
			attrs := map[string]string{sources.AttrPath: path}
			for _, source := range []sources.Source{
				&sources.Reader{Content: strings.NewReader("content"), Attributes: attrs, ShouldSkip: nil},
				fragmentSource{fragments: []sources.Fragment{{Raw: "", StartLine: 0, Attributes: attrs}}, err: nil},
			} {
				count := 0
				_, err = scanner.Scan(t.Context(), source, func(f report.Finding) error {
					count++
					require.Equal(t, path, f.Location.Path)
					require.Equal(t, path, f.Attr(sources.AttrPath))
					require.NotContains(t, f.Attributes, sources.AttrPath)
					return nil
				})
				require.NoError(t, err)
				if path == "skip.env" {
					require.Zero(t, count)
				} else {
					require.Equal(t, 1, count)
				}
				require.Equal(t, path, attrs[sources.AttrPath])
			}
		}
	}
}

func TestScannerOwnsRegexesFromPatternStrings(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{{
		ID:          "token",
		Regex:       `token=(?P<secret>[a-z]+)`,
		Path:        `\.env$`,
		SecretGroup: 1,
	}}}
	lazy := mustNew(t, cfg)
	eager := mustNew(t, cfg, WithPrecompile())
	require.NotSame(t, lazy.rulesBySpecificity[0].regex, eager.rulesBySpecificity[0].regex)
	require.NotSame(t, lazy.rulesBySpecificity[0].path, eager.rulesBySpecificity[0].path)

	cfg.Rules[0].Regex = `changed`
	cfg.Rules[0].Path = `\.txt$`
	for _, scanner := range []*Scanner{lazy, eager} {
		fragment := sources.Fragment{Raw: "token=secret", Attributes: map[string]string{sources.AttrPath: "app.env"}}
		findings := scanner.detectFragment(t.Context(), fragment)
		require.Len(t, findings, 1)
		require.Equal(t, "secret", findings[0].Match.Value)
		require.Equal(t, "secret", findings[0].Match.Captures["secret"])
		require.Equal(t, "app.env", findings[0].Location.Path)
		fragment.Attributes[sources.AttrPath] = "app.txt"
		require.Empty(t, scanner.detectFragment(t.Context(), fragment))
	}
}

func BenchmarkScanCaptureExtraction(b *testing.B) {
	var input strings.Builder
	for i := range 100 {
		fmt.Fprintf(&input, "token=secret-%06d account=user-%06d\n", i, i)
	}
	raw := input.String()
	for _, engine := range []regexp.Engine{regexp.Stdlib{}, re2.RE2{}} {
		b.Run(engine.Version(), func(b *testing.B) {
			for _, tc := range []struct{ name, pattern string }{
				{"no_captures", `secret-[0-9]{6}`},
				{"numbered", `token=(secret-[0-9]{6})`},
				{"named", `token=(?P<token>secret-[0-9]{6}) (?P<account>account=user-[0-9]{6})`},
				{"many_captures", `(?P<kind>token)=(?P<secret>secret)-(?P<id>[0-9]{6}) (?P<field>account)=(?P<user>user)-(?P<user_id>[0-9]{6})`},
			} {
				b.Run(tc.name, func(b *testing.B) {
					scanner, err := New(&config.Config{Rules: []config.Rule{{ID: "token", Regex: tc.pattern}}}, WithRegexEngine(engine), WithPrecompile(), WithWorkers(1))
					if err != nil {
						b.Fatal(err)
					}
					b.ReportAllocs()
					b.SetBytes(int64(len(raw)))
					for b.Loop() {
						if findings := scanner.ScanString(raw); len(findings) != 100 {
							b.Fatalf("got %d findings, want 100", len(findings))
						}
					}
				})
			}
		})
	}
}

func BenchmarkComponentProximity(b *testing.B) {
	for _, count := range []int{1, 10, 40} {
		var input strings.Builder
		for i := range count {
			fmt.Fprintf(&input, "PRIMARY%04d\nCOMPONENT%04d\n", i, i)
		}
		for input.Len() < 100_000 {
			input.WriteString(strings.Repeat(".", 999) + "\n")
		}
		raw := input.String()
		for _, window := range []string{"100000L", "100000C"} {
			b.Run(fmt.Sprintf("matches=%d/%s", count, window), func(b *testing.B) {
				scanner, err := New(&config.Config{Rules: []config.Rule{
					{ID: "primary", Regex: `PRIMARY[0-9]{4}`, Components: []config.Component{{RuleID: "component", Within: window}}},
					{ID: "component", Regex: `COMPONENT[0-9]{4}`, SkipReport: true},
				}}, WithPrecompile(), WithWorkers(1))
				if err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.SetBytes(int64(len(raw)))
				for b.Loop() {
					findings := scanner.ScanString(raw)
					if len(findings) != count || len(findings[0].ComponentSets) != count {
						b.Fatal("unexpected findings or component combinations")
					}
				}
			})
		}
	}
}

func mustPrefilter(t *testing.T, expression string) sources.SkipFunc {
	t.Helper()
	skip, err := prefilter.Compile(expression, prefilter.Options{})
	require.NoError(t, err)
	return skip
}

func TestPrefilterConstructionAndOwnership(t *testing.T) {
	skip, err := prefilter.Compile("", prefilter.Options{})
	require.NoError(t, err)
	require.Nil(t, skip)

	paths := []string{filepath.Join("fixtures", "ignored.env")}
	skip, err = prefilter.Compile("", prefilter.Options{ExcludedPaths: paths})
	require.NoError(t, err)
	paths[0] = "kept.env"
	assert.True(t, skip(map[string]string{sources.AttrPath: "fixtures/./ignored.env"}))
	assert.False(t, skip(map[string]string{sources.AttrPath: "kept.env"}))
	assert.False(t, skip(nil))

	for _, expression := range []string{
		`attributes[`, `finding.secret == "x"`,
		`tokenRatio(attributes.path) > 0`, `failsTokenEfficiency(attributes.path)`,
		`entropy(attributes.path) > 0`, `findMatch(attributes.path, "x") == "x"`,
		`intersects(["x"], ["x"])`, `http.get("https://example.com") != nil`,
	} {
		_, err := prefilter.Compile(expression, prefilter.Options{})
		require.Error(t, err, expression)
	}

	var output bytes.Buffer
	skip, err = prefilter.Compile(`int(attributes.path) > 0`, prefilter.Options{
		Logger: slog.New(slog.NewTextHandler(&output, nil)),
	})
	require.NoError(t, err)
	assert.False(t, skip(map[string]string{sources.AttrPath: "not-a-number"}))
	assert.Contains(t, output.String(), "prefilter eval error; not skipping")
}

func TestPrefilterConcurrentReuse(t *testing.T) {
	for _, expression := range []string{
		`matchesAny(attributes.path, ["^ignored\\.env$"])`,
		`startsWithAny(attributes.path, ["ignored"]) && containsAny(attributes.path, ["ENV"])`,
	} {
		skip := mustPrefilter(t, expression)
		var group sync.WaitGroup
		for i := range 20 {
			group.Go(func() {
				attrs := map[string]string{sources.AttrPath: "kept.env"}
				if i%2 == 0 {
					attrs[sources.AttrPath] = "ignored.env"
				}
				assert.Equal(t, i%2 == 0, skip(attrs))
				attrs[sources.AttrPath] = "kept.env"
				assert.False(t, skip(attrs))
			})
		}
		group.Wait()
	}
}

func TestScannerDoesNotOwnSourcePrefilter(t *testing.T) {
	cfg := testConfig()
	cfg.Prefilter = `invalid expression [`
	scanner := mustNew(t, cfg, WithPrecompile())
	require.Len(t, scanner.ScanString("secret-alpha"), 1)

	cfg.Prefilter = `attributes.path == "ignored.env"`
	skip := mustPrefilter(t, cfg.Prefilter)
	cfg.Prefilter = "true"
	checks := 0
	findings, err := collectSourceFindings(t.Context(), scanner, &sources.Reader{
		Content:    strings.NewReader("secret-alpha"),
		Attributes: map[string]string{sources.AttrPath: "kept.env"},
		ShouldSkip: func(attrs map[string]string) bool {
			checks++
			return skip(attrs)
		},
	})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Equal(t, 1, checks)
}

func TestFindingTextDoesNotRetainFragment(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "token", Regex: `token=(?P<value>[a-z]+)`, Components: []config.Component{{RuleID: "tenant", Within: "1L"}}},
		{ID: "tenant", Regex: `tenant=(?P<name>[a-z]+)`, SkipReport: true},
	}}
	scanner := mustNew(t, cfg, WithMatchContext("1L"))
	raw := strings.Repeat(".\n", 100_000) + "tenant=acme token=alpha token=beta\n" + strings.Repeat(".\n", 100_000)
	findings := scanner.ScanString(raw)
	require.Len(t, findings, 2)
	start := uintptr(unsafe.Pointer(unsafe.StringData(raw)))
	for _, finding := range findings {
		matches := []report.Match{finding.Match}
		require.Len(t, finding.ComponentSets, 1)
		matches = append(matches, finding.ComponentSets[0].Components[0].Match)
		for _, match := range matches {
			require.Equal(t, "tenant=acme token=alpha token=beta\n", match.Line)
			require.Equal(t, "tenant=acme token=alpha token=beta", match.Context)
			texts := []string{match.Full, match.Value, match.Line, match.Context}
			for _, capture := range match.Captures {
				texts = append(texts, capture)
			}
			for _, text := range texts {
				address := uintptr(unsafe.Pointer(unsafe.StringData(text)))
				require.False(t, address >= start && address < start+uintptr(len(raw)), "returned text retains the source fragment")
			}
		}
	}
	runtime.KeepAlive(raw)
	findings[0].Match.Captures["value"] = "changed"
	findings[0].ComponentSets[0].Components[0].Match.Captures["name"] = "changed"
	require.Equal(t, "beta", findings[1].Match.Captures["value"])
	require.Equal(t, "acme", findings[1].ComponentSets[0].Components[0].Match.Captures["name"])
}

func BenchmarkFindingText(b *testing.B) {
	for _, engine := range []regexp.Engine{regexp.Stdlib{}, re2.RE2{}} {
		b.Run(engine.Version(), func(b *testing.B) {
			for _, multiline := range []bool{false, true} {
				var input strings.Builder
				for i := range 1_000 {
					fmt.Fprintf(&input, "token=%06d%s", i, strings.Repeat(".", 88))
					if multiline {
						input.WriteByte('\n')
					}
				}
				raw := input.String()
				for _, mode := range []string{"accepted", "filtered", "missing_component"} {
					b.Run(fmt.Sprintf("multiline=%t/%s", multiline, mode), func(b *testing.B) {
						cfg := &config.Config{Rules: []config.Rule{{ID: "token", Regex: `token=(?P<value>[0-9]{6})`}}}
						want := 1_000
						switch mode {
						case "filtered":
							cfg.Rules[0].Filter = "true"
							want = 0
						case "missing_component":
							cfg.Rules[0].Components = []config.Component{{RuleID: "missing"}}
							cfg.Rules = append(cfg.Rules, config.Rule{ID: "missing", Regex: "MISSING", SkipReport: true})
							want = 0
						}
						scanner, err := New(cfg, WithRegexEngine(engine), WithPrecompile(), WithWorkers(1))
						if err != nil {
							b.Fatal(err)
						}
						b.ReportAllocs()
						b.SetBytes(int64(len(raw)))
						for b.Loop() {
							if findings := scanner.ScanString(raw); len(findings) != want {
								b.Fatalf("got %d findings, want %d", len(findings), want)
							}
						}
					})
				}
			}
		})
	}
}
