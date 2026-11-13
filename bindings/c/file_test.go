//go:build cgo && betterleaks_ffi

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"unicode/utf8"

	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
)

func TestScanFileMatchesBufferAcrossFragments(t *testing.T) {
	// A multibyte rune straddles the source reader's initial 100 KB read.
	input := strings.Repeat("x", 99_999) + "😀\nTOKEN=" + testToken + "\x00\n"
	path := filepath.Join(t.TempDir(), "配置.env")
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	s := scannerForTest(t, testConfig, nil)
	got, err := s.scanFile([]byte(path), []byte(`{"path":"spoofed","resource":"spoofed","custom":"value"}`))
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := json.Marshal(map[string]string{
		sources.AttrPath: filepath.ToSlash(path), sources.AttrResource: sources.ResourceFileContent,
		"custom": "value",
	})
	if err != nil {
		t.Fatal(err)
	}
	want, err := s.scan([]byte(input), attrs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("file scan differs from buffer scan:\ngot %s\nwant %s", got, want)
	}
	var result scanResponse
	if err := json.Unmarshal(got, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Location.StartLine != 2 {
		t.Fatalf("missing finding or wrong coordinates: %s", got)
	}
}

func TestScanFileFailuresReturnNoPartialResult(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.env")
	s := scannerForTest(t, testConfig, map[string]any{"max_input_bytes": 200_000, "max_findings": 1})
	for _, tc := range []struct {
		name, path string
		content    []byte
		attrs      []byte
		status     int32
	}{
		{name: "missing", path: filepath.Join(dir, "missing"), status: statusScan},
		{name: "directory", path: dir, status: statusInvalid},
		{name: "empty path", status: statusInvalid},
		{name: "NUL path", path: path + "\x00suffix", status: statusInvalid},
		{name: "invalid path encoding", path: string([]byte{0xff}), status: statusInvalid},
		{name: "long path", path: strings.Repeat("x", maxPathBytes+1), status: statusLimit},
		{name: "input bytes", path: path, content: bytes.Repeat([]byte("x"), 200_001), status: statusLimit},
		{name: "late invalid UTF-8", path: path, content: []byte(testToken + "\n" + strings.Repeat("x\n", 60_000) + "\xff"), status: statusInvalid},
		{name: "incomplete rune", path: path, content: []byte(testToken + "\n\xf0\x9f"), status: statusInvalid},
		{name: "findings", path: path, content: []byte(strings.Repeat(testToken+"\n", 2)), status: statusLimit},
		{name: "attributes", path: path, content: []byte(testToken), attrs: []byte(`{"custom":1}`), status: statusInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.content != nil {
				if err := os.WriteFile(path, tc.content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			result, err := s.scanFile([]byte(tc.path), tc.attrs)
			var api *apiError
			if result != nil || !errors.As(err, &api) || api.status != tc.status {
				t.Fatalf("want status %d without partial result, got %s, %v", tc.status, result, err)
			}
		})
	}
	if err := os.WriteFile(path, []byte(testToken), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.scanFile([]byte(path), nil); err != nil {
		t.Fatalf("scanner could not be reused after file errors: %v", err)
	}
}

func TestScanFilePathOnlyRuleRunsOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.env")
	if err := os.WriteFile(path, []byte(strings.Repeat("line\n", 60_000)), 0o600); err != nil {
		t.Fatal(err)
	}
	s := scannerForTest(t, "[[rules]]\nid='filename'\npath='tokens\\.env$'", map[string]any{"max_findings": 1})
	// Caller-supplied internal metadata must not suppress or duplicate matches.
	encoded, err := s.scanFile([]byte(path), []byte(`{"fs.first_fragment":"false"}`))
	if err != nil {
		t.Fatal(err)
	}
	var response scanResponse
	if err := json.Unmarshal(encoded, &response); err != nil || len(response.Findings) != 1 {
		t.Fatalf("path-only rule must match exactly once: %s, %v", encoded, err)
	}
}

func TestScanFileUsesDetectionBudgetAndFilters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.env")
	// Filter out every match: the candidate budget still applies before filters.
	cfg := `filter = "true"` + "\n[[rules]]\nid='dense'\nregex='.'\n"
	s := scannerForTest(t, cfg, nil)
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), maxCandidates+1), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := s.scanFile([]byte(path), nil)
	var api *apiError
	if result != nil || !errors.As(err, &api) || api.status != statusLimit || !errors.Is(err, scan.ErrLimitExceeded) {
		t.Fatalf("file scan bypassed detection budget: %s, %v", result, err)
	}
	if err := os.WriteFile(path, []byte(testToken), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, filter := range []string{
		`prefilter = '''attributes["resource"] == "fs.content" && attributes["path"] endsWith "tokens.env"'''`,
		`filter = '''attributes["custom"] == "skip"'''`,
	} {
		s = scannerForTest(t, filter+"\n"+testConfig, nil)
		encoded, err := s.scanFile([]byte(path), []byte(`{"custom":"skip"}`))
		if err != nil {
			t.Fatal(err)
		}
		var result scanResponse
		if err := json.Unmarshal(encoded, &result); err != nil || len(result.Findings) != 0 {
			t.Fatalf("file filters not honored: %s, %v", encoded, err)
		}
	}
}

func TestFileTextReaderUTF8AndLimits(t *testing.T) {
	for _, input := range []string{"", "ascii\x00", "é中😀�", "a\xff", "\x80", "\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xe2\x82", "\xf0\x9f\x98", "é\xf0\x9f"} {
		for size := 1; size <= 8; size++ {
			t.Run(fmt.Sprintf("%x/chunk%d", input, size), func(t *testing.T) {
				r := &fileTextReader{reader: strings.NewReader(input), remaining: len(input)}
				var output bytes.Buffer
				_, err := io.CopyBuffer(writerOnly{&output}, readerOnly{r}, make([]byte, size))
				if !utf8.ValidString(input) {
					var api *apiError
					if !errors.As(err, &api) || api.status != statusInvalid {
						t.Fatalf("invalid UTF-8 accepted: %v", err)
					}
				} else if err != nil || output.String() != input {
					t.Fatalf("UTF-8 split was not preserved: %q, %v", output.String(), err)
				}
			})
		}
	}
	for _, input := range []string{"abc", "abcd"} {
		r := &fileTextReader{reader: strings.NewReader(input), remaining: 3}
		_, err := io.ReadAll(r)
		if input == "abc" && err != nil {
			t.Fatal(err)
		}
		if input == "abcd" {
			var api *apiError
			if !errors.As(err, &api) || api.status != statusLimit {
				t.Fatalf("growth beyond byte limit accepted: %v", err)
			}
		}
	}
	readErr := errors.New("injected read error")
	r := &fileTextReader{reader: iotest.ErrReader(readErr), remaining: 10}
	if _, err := io.ReadAll(r); !errors.Is(err, readErr) {
		t.Fatalf("read error lost: %v", err)
	}
	s := scannerForTest(t, testConfig, nil)
	if result, err := s.scanReader(r, nil); result != nil || !errors.Is(err, readErr) {
		t.Fatalf("read failure returned a report or lost its cause: %s, %v", result, err)
	}
}

func FuzzFileTextReader(f *testing.F) {
	for _, input := range []string{"", "ascii\x00", "é中😀�", "a\xff", "\xf0\x9f", "\xed\xa0\x80"} {
		f.Add([]byte(input), uint8(1))
	}
	f.Fuzz(func(t *testing.T, input []byte, chunk uint8) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		// Exercise readers that return final data and EOF in the same Read.
		r := &fileTextReader{reader: iotest.DataErrReader(bytes.NewReader(input)), remaining: len(input)}
		var output bytes.Buffer
		_, err := io.CopyBuffer(writerOnly{&output}, readerOnly{r}, make([]byte, int(chunk)+1))
		if utf8.Valid(input) {
			if err != nil || !bytes.Equal(output.Bytes(), input) {
				t.Fatalf("valid UTF-8 changed: %x, %v", output.Bytes(), err)
			}
		} else {
			var api *apiError
			if !errors.As(err, &api) || api.status != statusInvalid {
				t.Fatalf("invalid UTF-8 accepted: %v", err)
			}
		}
	})
}

// Disable io.Copy's optional fast paths so tests control every read boundary.
type readerOnly struct{ io.Reader }
type writerOnly struct{ io.Writer }
