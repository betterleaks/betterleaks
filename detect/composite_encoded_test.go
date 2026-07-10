package detect

import (
	"testing"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

// compositeTestConfig defines a composite rule "foo" that requires "bar".
const compositeTestConfig = `
[[rules]]
id = "bar"
description = "bar dependency"
regex = '''bar-[a-z0-9]{8}'''
keywords = ["bar-"]

[[rules]]
id = "foo"
description = "foo composite"
regex = '''foo-[a-z0-9]{8}'''
keywords = ["foo-"]
[[rules.required]]
id = "bar"
`

// TestCompositeEncodedDependency verifies that a composite rule is reported when
// its primary and its required dependency surface at different decode depths.
// This is a regression test for composite rules being dropped when the
// dependency (or primary) only appears in encoded form — the failure mode that
// made slack-session-token (requires slack-session-cookie) invisible whenever
// the cookie was URL/base64-encoded.
func TestCompositeEncodedDependency(t *testing.T) {
	cfg, err := config.ParseTOMLString(compositeTestConfig, "composite.toml")
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	tests := []struct {
		name string
		raw  string
		// wantFoo asserts the composite "foo" is reported.
		wantFoo bool
		// wantComponent asserts the decoded dependency secret attached to "foo".
		wantComponent string
	}{
		{
			name:          "plaintext dependency (control)",
			raw:           "token = \"foo-abcd1234\"\ncookie = \"bar-cookie01\"\n",
			wantFoo:       true,
			wantComponent: "bar-cookie01",
		},
		{
			// "YmFyLWNvb2tpZTAx" == base64("bar-cookie01")
			name:          "base64-encoded dependency",
			raw:           "token = \"foo-abcd1234\"\ncookie = \"YmFyLWNvb2tpZTAx\"\n",
			wantFoo:       true,
			wantComponent: "bar-cookie01",
		},
		{
			// "Zm9vLWFiY2QxMjM0" == base64("foo-abcd1234"): the primary is encoded,
			// the dependency is plaintext (mirror of the above).
			name:          "base64-encoded primary",
			raw:           "token = \"Zm9vLWFiY2QxMjM0\"\ncookie = \"bar-cookie01\"\n",
			wantFoo:       true,
			wantComponent: "bar-cookie01",
		},
		{
			// "WW1GeUxXTnZiMnRwWlRBeA==" == base64(base64("bar-cookie01")): the
			// dependency only resolves after two decode passes.
			name:          "double-base64-encoded dependency",
			raw:           "token = \"foo-abcd1234\"\ncookie = \"WW1GeUxXTnZiMnRwWlRBeA==\"\n",
			wantFoo:       true,
			wantComponent: "bar-cookie01",
		},
		{
			name:    "dependency absent (negative control)",
			raw:     "token = \"foo-abcd1234\"\ncookie = \"nothing-here-at-all\"\n",
			wantFoo: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDetector(cfg)
			d.MaxDecodeDepth = 3

			findings := d.Detect(sources.Fragment{Raw: tt.raw})

			var foo *report.Finding
			for i := range findings {
				if findings[i].RuleID == "foo" {
					foo = &findings[i]
				}
			}

			if !tt.wantFoo {
				if foo != nil {
					t.Fatalf("expected no composite finding, got: %+v", *foo)
				}
				return
			}

			if foo == nil {
				t.Fatalf("expected composite rule \"foo\" to be reported; findings: %+v", findings)
			}
			if got := componentSecret(foo, "bar"); got != tt.wantComponent {
				t.Fatalf("expected \"bar\" component secret %q, got %q (finding: %+v)",
					tt.wantComponent, got, *foo)
			}
		})
	}
}

// compositeMultiDepConfig defines a composite "foo" that requires BOTH "bar"
// and "baz".
const compositeMultiDepConfig = `
[[rules]]
id = "bar"
description = "bar dependency"
regex = '''bar-[a-z0-9]{8}'''
keywords = ["bar-"]

[[rules]]
id = "baz"
description = "baz dependency"
regex = '''baz-[a-z0-9]{8}'''
keywords = ["baz-"]

[[rules]]
id = "foo"
description = "foo composite"
regex = '''foo-[a-z0-9]{8}'''
keywords = ["foo-"]
[[rules.required]]
id = "bar"
[[rules.required]]
id = "baz"
`

// TestCompositeMultipleDependenciesAcrossLayers verifies that a composite rule
// requiring multiple dependencies is reported when those dependencies surface
// at different decode depths (e.g. one plaintext, one base64, one double-base64).
func TestCompositeMultipleDependenciesAcrossLayers(t *testing.T) {
	cfg, err := config.ParseTOMLString(compositeMultiDepConfig, "composite-multidep.toml")
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	tests := []struct {
		name    string
		raw     string
		wantFoo bool
	}{
		{
			name:    "both dependencies plaintext",
			raw:     "t=\"foo-abcd1234\"\na=\"bar-cookie01\"\nb=\"baz-cookie02\"\n",
			wantFoo: true,
		},
		{
			// bar plaintext (depth 0), baz base64 (depth 1).
			name:    "deps split across depth 0 and 1",
			raw:     "t=\"foo-abcd1234\"\na=\"bar-cookie01\"\nb=\"YmF6LWNvb2tpZTAy\"\n",
			wantFoo: true,
		},
		{
			// bar base64 (depth 1), baz double-base64 (depth 2): both deps AND the
			// plaintext primary live at three different layers.
			name:    "deps split across depth 1 and 2",
			raw:     "t=\"foo-abcd1234\"\na=\"YmFyLWNvb2tpZTAx\"\nb=\"WW1GNkxXTnZiMnRwWlRBeQ==\"\n",
			wantFoo: true,
		},
		{
			// Only one of the two required deps is present -> composite must not fire.
			name:    "one dependency missing",
			raw:     "t=\"foo-abcd1234\"\na=\"bar-cookie01\"\nb=\"nothing-here-at-all\"\n",
			wantFoo: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDetector(cfg)
			d.MaxDecodeDepth = 3

			findings := d.Detect(sources.Fragment{Raw: tt.raw})

			var foo *report.Finding
			for i := range findings {
				if findings[i].RuleID == "foo" {
					foo = &findings[i]
				}
			}

			if !tt.wantFoo {
				if foo != nil {
					t.Fatalf("expected no composite finding, got: %+v", *foo)
				}
				return
			}

			if foo == nil {
				t.Fatalf("expected composite \"foo\" to be reported; findings: %+v", findings)
			}
			// Both required dependencies must be attached, decoded.
			if got := componentSecret(foo, "bar"); got != "bar-cookie01" {
				t.Fatalf("expected bar component \"bar-cookie01\", got %q (finding: %+v)", got, *foo)
			}
			if got := componentSecret(foo, "baz"); got != "baz-cookie02" {
				t.Fatalf("expected baz component \"baz-cookie02\", got %q (finding: %+v)", got, *foo)
			}
		})
	}
}

// componentSecret returns the secret of the first required component with the
// given rule ID across all of the finding's required sets, or "".
func componentSecret(f *report.Finding, ruleID string) string {
	for _, set := range f.RequiredSets {
		for _, comp := range set.Components {
			if comp.RuleID == ruleID {
				return comp.Secret
			}
		}
	}
	return ""
}
