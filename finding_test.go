package betterleaks_test

import (
	"testing"

	"github.com/betterleaks/betterleaks"
	"github.com/stretchr/testify/assert"
)

func TestRedact(t *testing.T) {
	tests := []struct {
		findings []betterleaks.Finding
		redact   bool
	}{
		{
			redact: true,
			findings: []betterleaks.Finding{
				{
					Match:  "line containing secret",
					Secret: "secret",
				},
			}},
	}
	for _, test := range tests {
		for _, f := range test.findings {
			f.Redact(100)
			assert.Equal(t, "REDACTED", f.Secret)
			assert.Equal(t, "line containing REDACTED", f.Match)
		}
	}
}

func TestMask(t *testing.T) {

	tests := map[string]struct {
		finding betterleaks.Finding
		percent uint
		expect  betterleaks.Finding
	}{
		"normal secret": {
			finding: betterleaks.Finding{Match: "line containing secret", Secret: "secret"},
			expect:  betterleaks.Finding{Match: "line containing se...", Secret: "se..."},
			percent: 75,
		},
		"empty secret": {
			finding: betterleaks.Finding{Match: "line containing", Secret: ""},
			expect:  betterleaks.Finding{Match: "line containing", Secret: ""},
			percent: 75,
		},
		"short secret": {
			finding: betterleaks.Finding{Match: "line containing", Secret: "ss"},
			expect:  betterleaks.Finding{Match: "line containing", Secret: "..."},
			percent: 75,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			f := test.finding
			e := test.expect
			f.Redact(test.percent)
			assert.Equal(t, e.Secret, f.Secret)
			assert.Equal(t, e.Match, f.Match)
		})
	}
}

func TestMaskSecret(t *testing.T) {

	tests := map[string]struct {
		secret  string
		percent uint
		expect  string
	}{
		"normal masking":  {secret: "secret", percent: 75, expect: "se..."},
		"high masking":    {secret: "secret", percent: 90, expect: "s..."},
		"low masking":     {secret: "secret", percent: 10, expect: "secre..."},
		"invalid masking": {secret: "secret", percent: 1000, expect: "..."},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := betterleaks.MaskSecret(test.secret, test.percent)
			assert.Equal(t, test.expect, got)
		})
	}
}
