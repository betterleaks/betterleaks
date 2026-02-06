package report

import (
	"encoding/json"
	"io"

	"github.com/betterleaks/betterleaks"
)

// --------------------------------------------------------------------------
// Legacy (gitleaks-compatible) JSON reporter.
//
// LegacyJsonReporter outputs findings using the gitleaks JSON shape, with
// flattened metadata fields (File, Commit, Author, …). Activated by --legacy.
// --------------------------------------------------------------------------

// LegacyJsonReporter writes findings in the gitleaks-compatible JSON format.
type LegacyJsonReporter struct{}

var _ betterleaks.Reporter = (*LegacyJsonReporter)(nil)

// legacyFindingWrapper wraps a Finding so that json.Encoder calls
// LegacyMarshalJSON instead of the default MarshalJSON.
type legacyFindingWrapper struct {
	f betterleaks.Finding
}

func (w legacyFindingWrapper) MarshalJSON() ([]byte, error) {
	return w.f.LegacyMarshalJSON()
}

func (t *LegacyJsonReporter) Write(w io.WriteCloser, findings []betterleaks.Finding) error {
	wrapped := make([]legacyFindingWrapper, len(findings))
	for i, f := range findings {
		wrapped[i] = legacyFindingWrapper{f: f}
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(wrapped)
}
