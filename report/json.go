package report

import (
	"encoding/json"
	"errors"
	"io"
)

type JsonReporter struct {
}

var _ Reporter = (*JsonReporter)(nil)
var _ StreamingReporter = (*JsonReporter)(nil)

func (t *JsonReporter) Write(w io.WriteCloser, findings []Finding) error {
	writer, err := t.NewWriter(w)
	if err != nil {
		return err
	}
	for _, finding := range findings {
		if err := writer.WriteFinding(finding); err != nil {
			return err
		}
	}
	return writer.Close()
}

func (t *JsonReporter) NewWriter(w io.Writer) (FindingWriter, error) {
	if w == nil {
		return nil, errors.New("report writer is nil")
	}
	if _, err := io.WriteString(w, "["); err != nil {
		return nil, err
	}
	return &jsonFindingWriter{w: w}, nil
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

// JsonlReporter writes one compact JSON finding per line.
type JsonlReporter struct{}

var _ Reporter = (*JsonlReporter)(nil)
var _ StreamingReporter = (*JsonlReporter)(nil)

func (r *JsonlReporter) Write(w io.WriteCloser, findings []Finding) error {
	writer, err := r.NewWriter(w)
	if err != nil {
		return err
	}
	for _, finding := range findings {
		if err := writer.WriteFinding(finding); err != nil {
			return err
		}
	}
	return writer.Close()
}

func (r *JsonlReporter) NewWriter(w io.Writer) (FindingWriter, error) {
	if w == nil {
		return nil, errors.New("report writer is nil")
	}
	return &jsonFindingWriter{
		w:       w,
		encoder: json.NewEncoder(w),
	}, nil
}
