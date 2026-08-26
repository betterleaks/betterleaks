package cmd

import "github.com/betterleaks/betterleaks/report"

// findingCollector counts findings and optionally buffers them for a report.
// Its zero value is count-only. It is used by a single Run result consumer and
// is not synchronized.
type findingCollector struct {
	count           int
	retainForReport bool
	reportFindings  []report.Finding
}

func newFindingCollector(retainForReport bool) *findingCollector {
	return &findingCollector{retainForReport: retainForReport}
}

func (c *findingCollector) Add(finding report.Finding) {
	c.count++
	if c.retainForReport {
		c.reportFindings = append(c.reportFindings, finding)
	}
}

func (c *findingCollector) Count() int {
	return c.count
}

func (c *findingCollector) ReportFindings() []report.Finding {
	return c.reportFindings
}
