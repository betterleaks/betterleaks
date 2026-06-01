package detect

import (
	"testing"

	"github.com/betterleaks/betterleaks/report"
	"github.com/stretchr/testify/assert"
)

func TestRedactFindings(t *testing.T) {
	findings := []report.Finding{
		{Secret: "sk_live_secret", Match: `stripe = "sk_live_secret"`},
	}
	RedactFindings(findings, 100)
	assert.Equal(t, "REDACTED", findings[0].Secret)
	assert.Equal(t, `stripe = "REDACTED"`, findings[0].Match)
}

func TestRedactFindings_zeroPercentIsNoOp(t *testing.T) {
	findings := []report.Finding{{Secret: "plain", Match: "plain"}}
	RedactFindings(findings, 0)
	assert.Equal(t, "plain", findings[0].Secret)
}

func TestRedactFindings_partialRedaction(t *testing.T) {
	findings := []report.Finding{
		{Secret: "sk_live_secret", Match: `stripe = "sk_live_secret"`},
	}
	RedactFindings(findings, 50)
	assert.Equal(t, "sk_live...", findings[0].Secret)
	assert.Equal(t, `stripe = "sk_live..."`, findings[0].Match)

	findings2 := []report.Finding{
		{Secret: "secret", Match: `key = "secret"`},
	}
	RedactFindings(findings2, 75)
	assert.Equal(t, "se...", findings2[0].Secret)
	assert.Equal(t, `key = "se..."`, findings2[0].Match)
}
