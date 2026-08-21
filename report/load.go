package report

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// LoadFindings reads a JSON or JSONL findings report from path or stdin ("-").
// Format is detected automatically: a leading "[" means a JSON array; otherwise JSONL.
func LoadFindings(path string) ([]Finding, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	return decodeFindings(r)
}

func decodeFindings(r io.Reader) ([]Finding, error) {
	br := bufio.NewReader(r)

	// Peek past leading whitespace to detect JSON array vs JSONL.
	first, err := peekFirstNonSpace(br)
	if err == io.EOF {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading input: %w", err)
	}

	dec := json.NewDecoder(br)
	if first == '[' {
		var findings []Finding
		if err := dec.Decode(&findings); err != nil {
			return nil, fmt.Errorf("decoding JSON: %w", err)
		}
		return findings, nil
	}

	// JSONL: one Finding object per line.
	var findings []Finding
	for dec.More() {
		var f Finding
		if err := dec.Decode(&f); err != nil {
			return nil, fmt.Errorf("decoding JSONL: %w", err)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func peekFirstNonSpace(br *bufio.Reader) (byte, error) {
	for {
		b, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
			if err := br.UnreadByte(); err != nil {
				return 0, err
			}
			return b, nil
		}
	}
}
