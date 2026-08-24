package report

import (
	"encoding/json"
	"io"
)

type JsonReporter struct {
}

var _ Reporter = (*JsonReporter)(nil)
var _ StreamReporter = (*JsonReporter)(nil)

func (t *JsonReporter) Write(w io.Writer, findings []Finding) error {
	return t.WriteStream(w, len(findings), iterateFindings(findings))
}

// WriteStream writes one encoded finding at a time. encoding/json otherwise
// builds the complete array in an internal buffer before the first write,
// temporarily duplicating the memory occupied by a large findings slice.
func (t *JsonReporter) WriteStream(w io.Writer, _ int, findings FindingIterator) error {
	if _, err := io.WriteString(w, "["); err != nil {
		return err
	}

	first := true
	err := findings(func(finding Finding) error {
		if first {
			first = false
			if _, err := io.WriteString(w, "\n"); err != nil {
				return err
			}
		} else if _, err := io.WriteString(w, ",\n"); err != nil {
			return err
		}

		encoded, err := json.Marshal(finding)
		if err != nil {
			return err
		}
		_, err = w.Write(encoded)
		return err
	})
	if err != nil {
		return err
	}

	if !first {
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
	}
	_, err = io.WriteString(w, "]\n")
	return err
}
