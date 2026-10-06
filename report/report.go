// Package report defines findings, credential results, and their output formats.
package report

import "time"

// ScanState reports whether scanning finished normally, independently of whether
// credentials were found. Recoverable warnings do not make a scan incomplete.
type ScanState string

const (
	ScanStateComplete   ScanState = "complete"
	ScanStateIncomplete ScanState = "incomplete"
)

// ScanMetadata describes a CLI scan invocation. All targets use one resolved
// configuration. ConfigHash includes detection policy and provider programs,
// but excludes runtime options. Finished is the time report finalization begins, including
// when the scan ends with an error.
type ScanMetadata struct {
	State              ScanState  `json:"state"`
	Source             ScanSource `json:"source"`
	Started            time.Time  `json:"started"`
	Finished           time.Time  `json:"finished"`
	BetterleaksVersion string     `json:"betterleaks_version"`
	ConfigHash         string     `json:"config_hash"`
	// BytesScanned counts inspected fragment bytes across all targets, after
	// exclusions and source archive expansion. It is not the input's disk size.
	BytesScanned uint64 `json:"bytes_scanned"`
	// NumFindings counts reported top-level findings after all output filters.
	// Each breakdown sums to NumFindings; component sets are not counted again.
	NumFindings      int              `json:"num_findings"`
	ConfidenceCounts ConfidenceCounts `json:"confidence_counts"`
	SeverityCounts   SeverityCounts   `json:"severity_counts"`
	StatusCounts     StatusCounts     `json:"status_counts"`
}

// ScanSource identifies the selected source and its selected targets, including
// targets not reached by an incomplete scan. Type is the resolved source kind,
// not "auto". Targets is omitted for stdin; remote URLs omit credentials,
// query strings, and fragments. Local paths retain the caller's spelling.
type ScanSource struct {
	Type    string   `json:"type"`
	Targets []string `json:"targets,omitempty"`
}

// ConfidenceCounts groups findings by confidence. None counts unset confidence;
// Other counts custom values supplied through source attributes.
type ConfidenceCounts struct {
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
	None   int `json:"none"`
	Other  int `json:"other"`
}

// SeverityCounts distinguishes absent severity from an unknown analysis result.
type SeverityCounts struct {
	High    int `json:"high"`
	Medium  int `json:"medium"`
	Unknown int `json:"unknown"`
	None    int `json:"none"`
}

// StatusCounts groups findings by credential validation outcome. None counts
// findings without validation. Provider errors do not imply an incomplete scan.
type StatusCounts struct {
	Valid           int `json:"valid"`
	Invalid         int `json:"invalid"`
	Revoked         int `json:"revoked"`
	NeedsValidation int `json:"needs_validation"`
	Unknown         int `json:"unknown"`
	Error           int `json:"error"`
	None            int `json:"none"`
}

// FindingWriter writes findings incrementally. Close finalizes the document;
// it never closes the caller's underlying writer. Calls must be serialized.
type FindingWriter interface {
	WriteFinding(Finding) error
	Close() error
}
