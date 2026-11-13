package scan

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/stretchr/testify/require"
)

func TestDeliveredFindingsOwnAttributes(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "content", Regex: "TOKEN"},
		{ID: "path", Path: `\.env$`},
	}}
	scanner := mustNew(t, cfg)
	attrs := map[string]string{sources.AttrPath: "config.env", "application": "original", "confidence": "high"}
	var findings []report.Finding
	_, err := scanner.Scan(t.Context(), &sources.Reader{
		Content: strings.NewReader("TOKEN\nTOKEN"), Attributes: attrs,
	}, func(finding report.Finding) error {
		require.Equal(t, "original", finding.Attributes["application"])
		require.Equal(t, "config.env", finding.Location.Path)
		require.Equal(t, "high", finding.Confidence)
		require.NotContains(t, finding.Attributes, sources.AttrPath)
		require.NotContains(t, finding.Attributes, "confidence")
		finding.Attributes["application"] = fmt.Sprint(len(findings))
		findings = append(findings, finding)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, findings, 3)
	for i, finding := range findings {
		require.Equal(t, fmt.Sprint(i), finding.Attributes["application"])
	}
	require.Equal(t, "original", attrs["application"])
	require.Equal(t, "high", attrs["confidence"])
	require.Equal(t, "config.env", attrs[sources.AttrPath])
}

func TestBorrowedAttributesPreserveSCMLinksInFilters(t *testing.T) {
	const remote = "https://github.com/example/repo"
	const link = remote + "/blob/abcdef/config.env#L1"
	cfg := &config.Config{Rules: []config.Rule{
		{ID: "content", Regex: "TOKEN", FilterExpr: `attributes.url != "` + link + `"`},
		{ID: "path", Path: `\.env$`, FilterExpr: `attributes.url != "source-url"`},
	}}
	scanner := mustNew(t, cfg)
	attrs := map[string]string{
		sources.AttrPath: "config.env", sources.AttrURL: "source-url",
		sources.AttrGitPlatform: "github", sources.AttrGitRemoteURL: remote, sources.AttrGitSHA: "abcdef",
	}
	got := make(map[string]string)
	_, err := scanner.Scan(t.Context(), &sources.Reader{
		Content: strings.NewReader("TOKEN\nTOKEN"), Attributes: attrs,
	}, func(finding report.Finding) error {
		got[finding.RuleID] = finding.Attributes[sources.AttrURL]
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, map[string]string{"content": link, "path": "source-url"}, got)
	require.Equal(t, "source-url", attrs[sources.AttrURL])
}

func TestStoppedScanDoesNotCloneAttributesForUndeliveredFindings(t *testing.T) {
	scanner := mustNew(t, &config.Config{Rules: []config.Rule{{ID: "token", Regex: "TOKEN"}}}, WithWorkers(1))
	input := strings.Repeat("TOKEN\n", 2000)
	stop := errors.New("stop after two findings")
	allocated := func(attrs map[string]string) uint64 {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		count := 0
		_, err := scanner.Scan(t.Context(), &sources.Reader{
			Content: strings.NewReader(input), Attributes: attrs,
		}, func(report.Finding) error {
			count++
			if count == 2 {
				return stop
			}
			return nil
		})
		runtime.ReadMemStats(&after)
		require.ErrorIs(t, err, stop)
		return after.TotalAlloc - before.TotalAlloc
	}
	baseline := allocated(nil)
	attrs := make(map[string]string, 1024)
	for i := range 1024 {
		attrs[fmt.Sprintf("key%04d", i)] = "value"
	}
	withAttributes := allocated(attrs)
	// Previously the 2,000 per-finding map copies added about 157 MiB even
	// though the handler stopped after two findings. Allow generous overhead
	// for source and delivered-finding copies across Go versions and race builds.
	require.Less(t, withAttributes, baseline+(4<<20))
	t.Logf("allocated without attributes: %.2f MiB; with 1024 attributes: %.2f MiB",
		float64(baseline)/(1<<20), float64(withAttributes)/(1<<20))
}
