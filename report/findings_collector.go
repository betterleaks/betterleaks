package report

// FindingsCollector counts findings and optionally retains them for later
// reporting. Its zero value is a count-only collector. A FindingsCollector is
// intended to be used by a single result consumer and is not synchronized.
type FindingsCollector struct {
	count  int
	retain bool

	findings []Finding
}

// NewFindingsCollector creates a collector. When retain is false, Add does not
// keep references to findings, allowing their memory to be reclaimed promptly.
func NewFindingsCollector(retain bool) *FindingsCollector {
	return &FindingsCollector{
		count:    0,
		retain:   retain,
		findings: nil,
	}
}

// Add records an accepted finding.
func (c *FindingsCollector) Add(finding Finding) {
	c.count++
	if c.retain {
		c.findings = append(c.findings, finding)
	}
}

// Len returns the total number of findings added, whether retained or not.
func (c *FindingsCollector) Len() int {
	return c.count
}

// Findings returns retained findings. It returns nil in count-only mode.
func (c *FindingsCollector) Findings() []Finding {
	return c.findings
}
