package report

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindingsCollectorCountsWithoutRetaining(t *testing.T) {
	collector := NewFindingsCollector(false)
	payload := strings.Repeat("x", 32*1024)

	const count = 10_000
	for range count {
		var finding Finding
		finding.Secret = payload
		finding.MatchContext = payload
		collector.Add(finding)
	}

	require.Equal(t, count, collector.Len())
	require.Nil(t, collector.Findings())
}

func TestFindingsCollectorRetainsFindings(t *testing.T) {
	collector := NewFindingsCollector(true)
	var first Finding
	first.RuleID = "first"
	first.Secret = "one"
	var second Finding
	second.RuleID = "second"
	second.Secret = "two"
	want := []Finding{first, second}
	for _, finding := range want {
		collector.Add(finding)
	}

	require.Equal(t, len(want), collector.Len())
	require.Equal(t, want, collector.Findings())
}

func TestZeroValueFindingsCollectorCountsWithoutRetaining(t *testing.T) {
	var collector FindingsCollector
	var finding Finding
	collector.Add(finding)

	require.Equal(t, 1, collector.Len())
	require.Nil(t, collector.Findings())
}
