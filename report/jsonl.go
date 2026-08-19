package report

import (
	"encoding/json"
	"io"
)

// JsonlReporter writes findings as JSON Lines (NDJSON): one compact JSON
// object per line. An empty finding set produces empty output.
type JsonlReporter struct {
}

var _ Reporter = (*JsonlReporter)(nil)

func (r *JsonlReporter) Write(w io.WriteCloser, findings []Finding) error {
	encoder := json.NewEncoder(w)
	for i := range findings {
		if err := encoder.Encode(&findings[i]); err != nil {
			return err
		}
	}
	return nil
}
