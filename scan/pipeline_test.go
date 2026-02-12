package scan

import (
	"context"
	"sort"
	"testing"

	"github.com/betterleaks/betterleaks"
	"github.com/betterleaks/betterleaks/config"
	_ "github.com/betterleaks/betterleaks/sources/file"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadConfig loads a TOML config file via viper.
func loadConfig(t *testing.T, path string) config.Config {
	t.Helper()
	v := viper.New()
	v.SetConfigFile(path)
	require.NoError(t, v.ReadInConfig())
	var vc config.ViperConfig
	require.NoError(t, v.Unmarshal(&vc))
	cfg, err := vc.Translate()
	require.NoError(t, err)
	return cfg
}

// processTestFragment runs a fragment through the full pipeline and returns findings.
func processTestFragment(t *testing.T, cfg config.Config, raw, path string, maxDecodeDepth int) []betterleaks.Finding {
	t.Helper()
	ctx := context.Background()
	scanner := NewScanner(ctx, &cfg, maxDecodeDepth, false, 1)
	pipeline := NewPipeline(cfg, nil, *scanner)

	fragment := betterleaks.Fragment{
		Raw:  raw,
		Path: path,
		Resource: &betterleaks.Resource{
			Name:   path,
			Path:   path,
			Kind:   "file_content",
			Source: "file",
			Metadata: map[string]string{
				betterleaks.MetaPath: path,
			},
		},
	}

	findings, err := pipeline.ProcessFragment(ctx, fragment)
	require.NoError(t, err)
	return findings
}

// expectedFinding describes what we expect a finding to look like.
// Fields left zero/nil are not checked.
type expectedFinding struct {
	RuleID      string
	Secret      string
	Match       string
	Line        string
	Tags        []string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
	Entropy     float64
}

// compare checks that every expected finding has a matching actual finding.
// Findings are matched by (RuleID, Secret) pair. Tags are compared as sets.
func compare(t *testing.T, actual []betterleaks.Finding, expected []expectedFinding) {
	t.Helper()

	// Log all actual findings for debugging.
	for i, f := range actual {
		t.Logf("actual[%d]: rule=%-35s secret=%.60q tags=%v line=%d:%d col=%d:%d",
			i, f.RuleID, f.Secret, f.Tags, f.StartLine, f.EndLine, f.StartColumn, f.EndColumn)
	}

	// Build a lookup: (ruleID, secret) → []Finding to handle duplicates.
	type key struct{ rule, secret string }
	lookup := map[key][]betterleaks.Finding{}
	for _, f := range actual {
		k := key{f.RuleID, f.Secret}
		lookup[k] = append(lookup[k], f)
	}

	for i, exp := range expected {
		k := key{exp.RuleID, exp.Secret}
		candidates := lookup[k]
		if len(candidates) == 0 {
			t.Errorf("expected[%d]: no finding with rule=%q secret=%q", i, exp.RuleID, exp.Secret)
			continue
		}

		// Find the best match (by StartLine if specified, else first).
		var f *betterleaks.Finding
		if exp.StartLine > 0 {
			for j := range candidates {
				if candidates[j].StartLine == exp.StartLine {
					f = &candidates[j]
					break
				}
			}
			if f == nil {
				t.Errorf("expected[%d]: rule=%q secret=%q found but not at line %d (got lines %v)",
					i, exp.RuleID, exp.Secret, exp.StartLine, candidateLines(candidates))
				continue
			}
		} else {
			f = &candidates[0]
		}

		if exp.Match != "" {
			assert.Equal(t, exp.Match, f.Match, "expected[%d] Match", i)
		}
		if exp.Line != "" {
			assert.Equal(t, exp.Line, f.Line, "expected[%d] Line", i)
		}
		if exp.StartLine > 0 {
			assert.Equal(t, exp.StartLine, f.StartLine, "expected[%d] StartLine", i)
		}
		if exp.EndLine > 0 {
			assert.Equal(t, exp.EndLine, f.EndLine, "expected[%d] EndLine", i)
		}
		if exp.StartColumn > 0 {
			assert.Equal(t, exp.StartColumn, f.StartColumn, "expected[%d] StartColumn", i)
		}
		if exp.EndColumn > 0 {
			assert.Equal(t, exp.EndColumn, f.EndColumn, "expected[%d] EndColumn", i)
		}
		if exp.Entropy > 0 {
			assert.InDelta(t, exp.Entropy, f.Entropy, 0.001, "expected[%d] Entropy", i)
		}
		if len(exp.Tags) > 0 {
			compareTags(t, f.Tags, exp.Tags, i)
		}
	}

	if len(actual) != len(expected) {
		t.Errorf("finding count mismatch: got %d, want %d", len(actual), len(expected))
	}
}

func compareTags(t *testing.T, actual, expected []string, idx int) {
	t.Helper()
	sortedActual := make([]string, len(actual))
	copy(sortedActual, actual)
	sort.Strings(sortedActual)

	sortedExpected := make([]string, len(expected))
	copy(sortedExpected, expected)
	sort.Strings(sortedExpected)

	assert.Equal(t, sortedExpected, sortedActual, "expected[%d] Tags", idx)
}

func candidateLines(findings []betterleaks.Finding) []int {
	lines := make([]int, len(findings))
	for i, f := range findings {
		lines[i] = f.StartLine
	}
	return lines
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
Look at this value: %4EjMzMjU2NkE2MzZENTYzMDUwNTY3MDQ4%4eTY2RDcwNjk0RDY5NTUzMTRENkQ3ODYx%25%34%45TE3QTQ2MzY1NzZDNjQ0RjY1NTY3MDU5NTU1ODUyNkI2MjUzNTUzMDRFNkU0RTZCNTYzMTU1MzkwQQ== # isn't it crazy?
## Multi percent encode two random characters close to the bounds of the base64
## encoded data to make sure that the bounds are still correctly calculated
secret=ZG%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%36%25%33%31%25%32%35%25%33%32%25%33%35%25%32%35%25%33%33%25%33%36%25%32%35%25%33%33%25%33%322RlZC1zZWNyZXQtd%25%36%64%25%34%36%25%37%33dWU=
## The similar to the above but also touching the edge of the base64
secret=%25%35%61%25%34%37%25%35%36jb2RlZC1zZWNyZXQtdmFsdWU%25%32%35%25%33%33%25%36%34
## The similar to the above but also touching and overlapping the base64
secret%3D%25%35%61%25%34%37%25%35%36jb2RlZC1zZWNyZXQtdmFsdWU%25%32%35%25%33%33%25%36%34
`

type pipelineTest struct {
	cfgPath          string
	raw              string
	filePath         string
	maxDecodeDepth   int
	expectedFindings []expectedFinding
}

var pipelineTests = map[string]pipelineTest{
	"detect encoded": {
		cfgPath:        "../testdata/config/encoded.toml",
		raw:            encodedTestValues,
		filePath:       "tmp.go",
		maxDecodeDepth: 10,
		expectedFindings: []expectedFinding{
			{ // Plain text key captured by normal rule
				RuleID:      "private-key",
				Secret:      "-----BEGIN PRIVATE KEY-----\n135f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb\nu+QDkg0spw==\n-----END PRIVATE KEY-----",
				Match:       "-----BEGIN PRIVATE KEY-----\n135f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb\nu+QDkg0spw==\n-----END PRIVATE KEY-----",
				Line:        "-----BEGIN PRIVATE KEY-----\n135f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb\nu+QDkg0spw==\n-----END PRIVATE KEY-----",
				Tags:        []string{},
				StartLine:   3,
				EndLine:     6,
				StartColumn: 2,
				EndColumn:   26,
				Entropy:     5.350665,
			},
			{ // Encoded key captured by custom b64 regex rule
				RuleID:      "b64-encoded-private-key",
				Secret:      "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCjQzNWYvYlJVQkhyYkhxTFkveFMzSTdPdGgrOHJnRyswdEJ3Zk1jYmswNVNneHE2UVV6U1lJUUFvcCtXdnNUd2syc1IrQzM4ZzBNbmIKdStRRGtnMHNwdz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K",
				Match:       "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCjQzNWYvYlJVQkhyYkhxTFkveFMzSTdPdGgrOHJnRyswdEJ3Zk1jYmswNVNneHE2UVV6U1lJUUFvcCtXdnNUd2syc1IrQzM4ZzBNbmIKdStRRGtnMHNwdz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K",
				Line:        "private_key: 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCjQzNWYvYlJVQkhyYkhxTFkveFMzSTdPdGgrOHJnRyswdEJ3Zk1jYmswNVNneHE2UVV6U1lJUUFvcCtXdnNUd2syc1IrQzM4ZzBNbmIKdStRRGtnMHNwdz09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K'",
				Tags:        []string{},
				StartLine:   9,
				EndLine:     9,
				StartColumn: 16,
				EndColumn:   207,
				Entropy:     5.386114,
			},
			{ // Encoded key captured by plain text rule using the decoder
				RuleID:      "private-key",
				Secret:      "-----BEGIN PRIVATE KEY-----\n435f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb\nu+QDkg0spw==\n-----END PRIVATE KEY-----",
				Match:       "-----BEGIN PRIVATE KEY-----\n435f/bRUBHrbHqLY/xS3I7Oth+8rgG+0tBwfMcbk05Sgxq6QUzSYIQAop+WvsTwk2sR+C38g0Mnb\nu+QDkg0spw==\n-----END PRIVATE KEY-----",
				Tags:        []string{"decoded:base64", "decode-depth:1"},
				StartLine:   9,
				EndLine:     9,
				StartColumn: 16,
				EndColumn:   207,
				Entropy:     5.350665,
			},
			{ // Encoded small secret decoded from base64
				RuleID:      "small-secret",
				Secret:      "small-secret",
				Match:       "small-secret",
				Tags:        []string{"decoded:base64", "decode-depth:1"},
				StartLine:   16,
				EndLine:     16,
				StartColumn: 2,
				EndColumn:   17,
				Entropy:     3.084962,
			},
			{ // Secret where the decoded match goes outside the encoded value
				RuleID:      "overlapping",
				Secret:      "decoded-secret-value00",
				Match:       "secret=decoded-secret-value00",
				Tags:        []string{"decoded:base64", "decode-depth:1"},
				StartLine:   19,
				EndLine:     19,
				StartColumn: 2,
				EndColumn:   40,
				Entropy:     3.442862,
			},
			{ // Confirm decoded password is detected (no allowlist)
				RuleID:      "decoded-password-dont-ignore",
				Secret:      "lRqBK-z5kf4-please-ignore-me-X-XIJM2Pddw",
				Match:       "password=\"lRqBK-z5kf4-please-ignore-me-X-XIJM2Pddw\"",
				Tags:        []string{"decoded:base64", "decode-depth:1"},
				StartLine:   24,
				EndLine:     24,
				StartColumn: 2,
				EndColumn:   68,
				Entropy:     4.584183,
			},
			{ // Hex encoded data check
				RuleID:      "overlapping",
				Secret:      "decoded-secret-valuevHEX",
				Match:       "secret=decoded-secret-valuevHEX",
				Tags:        []string{"decoded:hex", "decode-depth:1"},
				StartLine:   27,
				EndLine:     27,
				StartColumn: 2,
				EndColumn:   56,
				Entropy:     3.653107,
			},
			{ // Partial percent encoded data
				RuleID:      "overlapping",
				Secret:      "decoded-secret-valuev2",
				Match:       "secret=decoded-secret-valuev2",
				Tags:        []string{"decoded:percent", "decode-depth:1"},
				StartLine:   31,
				EndLine:     31,
				StartColumn: 2,
				EndColumn:   42,
				Entropy:     3.442862,
			},
			{ // Scattered percent encoded data
				RuleID:      "overlapping",
				Secret:      "decoded-secret-valuev3",
				Match:       "secret=decoded-secret-valuev3",
				Tags:        []string{"decoded:percent", "decode-depth:1"},
				StartLine:   33,
				EndLine:     33,
				StartColumn: 2,
				EndColumn:   46,
				Entropy:     3.442862,
			},
			{ // AWS IAM unique identifier inside JWT at depth 2
				RuleID:      "aws-iam-unique-identifier",
				Secret:      "ASIAIOSFODNN7LXM10JI",
				Match:       " ASIAIOSFODNN7LXM10JI",
				Tags:        []string{"decoded:base64", "decode-depth:2"},
				StartLine:   12,
				EndLine:     12,
				StartColumn: 39,
				EndColumn:   344,
				Entropy:     3.684183,
			},
			{ // AWS secret access key inside JWT at depth 2
				RuleID:      "aws-secret-access-key",
				Secret:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEFUCDlEX1A",
				Match:       "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEFUCDlEX1A",
				Tags:        []string{"decoded:base64", "decode-depth:2"},
				StartLine:   12,
				EndLine:     12,
				StartColumn: 39,
				EndColumn:   344,
				Entropy:     4.721928,
			},
			{ // Double-encoded b64: secret=decoded-secret-value at depth 2
				RuleID:      "overlapping",
				Secret:      "decoded-secret-value",
				Match:       "secret=decoded-secret-value",
				Tags:        []string{"decoded:base64", "decode-depth:2"},
				StartLine:   21,
				EndLine:     21,
				StartColumn: 2,
				EndColumn:   49,
				Entropy:     3.303701,
			},
			{ // Percent+hex touching encodings at depth 2
				RuleID:      "overlapping",
				Secret:      "decoded-secret-valuev5",
				Match:       "secret=decoded-secret-valuev5",
				Tags:        []string{"decoded:percent", "decoded:hex", "decode-depth:2"},
				StartLine:   41,
				EndLine:     41,
				StartColumn: 2,
				EndColumn:   54,
				Entropy:     3.442862,
			},
			{ // Multiple percent encodings in a single layer base64 at depth 2
				RuleID:      "overlapping",
				Secret:      "decoded-secret-valuex86",
				Match:       "secret=decoded-secret-valuex86",
				Tags:        []string{"decoded:percent", "decoded:base64", "decode-depth:2"},
				StartLine:   43,
				EndLine:     43,
				StartColumn: 2,
				EndColumn:   44,
				Entropy:     3.638147,
			},
			{ // Base64 encoded partially percent encoded value at depth 2
				RuleID:      "overlapping",
				Secret:      "decoded-secret-value",
				Match:       "secret=decoded-secret-value",
				Tags:        []string{"decoded:percent", "decoded:base64", "decode-depth:2"},
				StartLine:   45,
				EndLine:     45,
				StartColumn: 2,
				EndColumn:   52,
				Entropy:     3.303701,
			},
			{ // Single percent encoding in multi-layer b64 at depth 3
				RuleID:      "overlapping",
				Secret:      "decoded-secret-valuev4",
				Match:       "secret=decoded-secret-valuev4",
				Tags:        []string{"decoded:percent", "decoded:base64", "decode-depth:3"},
				StartLine:   39,
				EndLine:     39,
				StartColumn: 2,
				EndColumn:   55,
				Entropy:     3.442862,
			},
			{ // Percent touching b64 edge at depth 4
				RuleID:      "overlapping",
				Secret:      "decoded-secret-value",
				Match:       "secret=decoded-secret-value",
				Tags:        []string{"decoded:percent", "decoded:base64", "decode-depth:4"},
				StartLine:   53,
				EndLine:     53,
				StartColumn: 2,
				EndColumn:   86,
				Entropy:     3.303701,
			},
			{ // Percent overlapping b64 at depth 4
				RuleID:      "overlapping",
				Secret:      "decoded-secret-value",
				Match:       "secret=decoded-secret-value",
				Tags:        []string{"decoded:percent", "decoded:base64", "decode-depth:4"},
				StartLine:   55,
				EndLine:     55,
				StartColumn: 2,
				EndColumn:   88,
				Entropy:     3.303701,
			},
			{ // Multi percent encode near b64 bounds at depth 5
				RuleID:      "overlapping",
				Secret:      "decoded-secret-value",
				Match:       "secret=decoded-secret-value",
				Tags:        []string{"decoded:percent", "decoded:base64", "decode-depth:5"},
				StartLine:   51,
				EndLine:     51,
				StartColumn: 2,
				EndColumn:   300,
				Entropy:     3.303701,
			},
			{ // The "went through a lot" line at depth 7
				RuleID:      "overlapping",
				Secret:      "decoded-secret-value",
				Match:       "secret=decoded-secret-value",
				Tags:        []string{"decoded:percent", "decoded:hex", "decoded:base64", "decode-depth:7"},
				StartLine:   48,
				EndLine:     48,
				StartColumn: 22,
				EndColumn:   177,
				Entropy:     3.303701,
			},
		},
	},
}

func TestPipeline(t *testing.T) {
	for name, tt := range pipelineTests {
		t.Run(name, func(t *testing.T) {
			cfg := loadConfig(t, tt.cfgPath)
			findings := processTestFragment(t, cfg, tt.raw, tt.filePath, tt.maxDecodeDepth)
			compare(t, findings, tt.expectedFindings)
		})
	}
}
