package report

import (
	"encoding/json"
	"io"

	"github.com/betterleaks/betterleaks"
)

type JsonReporter struct {
}

var _ betterleaks.Reporter = (*JsonReporter)(nil)

func (t *JsonReporter) Write(w io.WriteCloser, findings []betterleaks.Finding) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(findings)
}
