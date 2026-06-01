package detect

import "github.com/betterleaks/betterleaks/report"

// RedactFindings applies configured redaction to findings before they are written
// to a report file or stdout. The legacy detect path previously redacted only in
// Detector.Findings(); the git/dir/github paths collect findings separately and
// must redact in the shared report writer (cmd.findingSummaryAndExit).
func RedactFindings(findings []report.Finding, percent uint) {
	if percent == 0 {
		return
	}
	for i := range findings {
		findings[i].Redact(percent)
	}
}
