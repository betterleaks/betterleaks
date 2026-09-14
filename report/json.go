package report

import (
	"encoding/json"
	"errors"
	"io"
)

// NewJSONWriter starts a JSON array. Close finishes the array without closing w.
func NewJSONWriter(w io.Writer) (FindingWriter, error) {
	if w == nil {
		return nil, errors.New("report writer is nil")
	}
	if _, err := io.WriteString(w, "["); err != nil {
		return nil, err
	}
	return &jsonFindingWriter{w: w}, nil
}

// WriteJSON writes findings as a JSON array without closing w.
func WriteJSON(w io.Writer, findings []Finding) error {
	writer, err := NewJSONWriter(w)
	if err != nil {
		return err
	}
	return writeFindings(writer, findings)
}

func writeFindings(w FindingWriter, findings []Finding) error {
	for _, finding := range findings {
		if err := w.WriteFinding(finding); err != nil {
			return err
		}
	}
	return w.Close()
}

type jsonFindingWriter struct {
	w       io.Writer
	count   int
	closed  bool
	encoder *json.Encoder
}

func (w *jsonFindingWriter) WriteFinding(finding Finding) error {
	if w.closed {
		return errors.New("report writer is closed")
	}
	if w.encoder != nil {
		return w.encoder.Encode(finding)
	}

	encoded, err := json.MarshalIndent(finding, " ", " ")
	if err != nil {
		return err
	}
	separator := "\n "
	if w.count > 0 {
		separator = ",\n "
	}
	if _, err := io.WriteString(w.w, separator); err != nil {
		return err
	}
	if _, err := w.w.Write(encoded); err != nil {
		return err
	}
	w.count++
	return nil
}

func (w *jsonFindingWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if w.encoder != nil {
		return nil
	}
	if w.count == 0 {
		_, err := io.WriteString(w.w, "]\n")
		return err
	}
	_, err := io.WriteString(w.w, "\n]\n")
	return err
}

// NewJSONLWriter writes one compact JSON finding per line. Close leaves w open.
func NewJSONLWriter(w io.Writer) (FindingWriter, error) {
	if w == nil {
		return nil, errors.New("report writer is nil")
	}
	return &jsonFindingWriter{w: w, encoder: json.NewEncoder(w)}, nil
}

// WriteJSONL writes findings as JSONL without closing w.
func WriteJSONL(w io.Writer, findings []Finding) error {
	writer, err := NewJSONLWriter(w)
	if err != nil {
		return err
	}
	return writeFindings(writer, findings)
}
