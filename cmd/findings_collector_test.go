package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/report"
)

func TestFindingCollectorCountsWithoutRetaining(t *testing.T) {
	collector := newFindingCollector(false)
	payload := strings.Repeat("x", 32*1024)

	const count = 10_000
	for range count {
		collector.Add(report.Finding{
			Secret:       payload,
			MatchContext: payload,
		})
	}

	require.Equal(t, count, collector.Count())
	require.Nil(t, collector.ReportFindings())
}

func TestFindingCollectorRetainsReportFindings(t *testing.T) {
	collector := newFindingCollector(true)
	want := []report.Finding{
		{RuleID: "first", Secret: "one"},
		{RuleID: "second", Secret: "two"},
	}
	for _, finding := range want {
		collector.Add(finding)
	}

	require.Equal(t, len(want), collector.Count())
	require.Equal(t, want, collector.ReportFindings())
}

func TestZeroValueFindingCollectorCountsWithoutRetaining(t *testing.T) {
	var collector findingCollector
	collector.Add(report.Finding{})

	require.Equal(t, 1, collector.Count())
	require.Nil(t, collector.ReportFindings())
}
