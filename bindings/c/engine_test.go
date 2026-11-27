//go:build cgo && betterleaks_ffi

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/regexp/re2"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
)

const testConfig = `
[[rules]]
id = "example"
description = "Example token"
regex = '''example_[a-f0-9]{32}'''
keywords = ["example_"]
`

const testToken = "example_0123456789abcdef0123456789abcdef"

func scannerForTest(t *testing.T, cfg string, extra map[string]any) *nativeScanner {
	t.Helper()
	options := map[string]any{"config_toml": cfg, "workers": 2}
	for key, value := range extra {
		options[key] = value
	}
	encoded, err := json.Marshal(options)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newScanner(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMatchesGoSDK(t *testing.T) {
	input := "é\x00TOKEN=" + testToken + "\n"
	native := scannerForTest(t, testConfig, nil)
	encoded, err := native.scan([]byte(input), []byte(`{"path":"config.env"}`))
	if err != nil {
		t.Fatal(err)
	}
	var response scanResponse
	if err := json.Unmarshal(encoded, &response); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseTOMLString(testConfig, "")
	if err != nil {
		t.Fatal(err)
	}
	scanner, err := scan.New(cfg, scan.WithRegexEngine(re2.RE2{}))
	if err != nil {
		t.Fatal(err)
	}
	var expected []report.Finding
	summary, err := scanner.Scan(context.Background(), &sources.Reader{
		Content: strings.NewReader(input), Attributes: map[string]string{"path": "config.env"},
	}, func(f report.Finding) error { expected = append(expected, f); return nil })
	if err != nil {
		t.Fatal(err)
	}
	// Compare report semantics, including custom marshaling and omitted fields.
	want, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(response.Findings)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(got) || response.Summary.BytesInspected != summary.BytesInspected {
		t.Fatalf("native response differs from Go SDK: %s vs %s", got, want)
	}
	if len(response.Findings) != 1 || response.Findings[0].Match.Value != testToken {
		t.Fatalf("unexpected findings: %d", len(response.Findings))
	}
}

func TestLimitsAndErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts string
		code int32
	}{
		{"unknown option", `{"wokers":1}`, statusInvalid},
		{"null options", `null`, statusInvalid},
		{"trailing value", `{} {}`, statusInvalid},
		{"invalid config", `{"config_toml":"not = [valid"}`, statusConfig},
		{"regex compilation", `{"config_toml":"[[rules]]\nid='broken'\nregex='('"}`, statusConfig},
		{"input limit", `{"max_input_bytes":0}`, statusInvalid},
		{"finding limit", `{"max_findings":100001}`, statusInvalid},
		{"worker limit", `{"workers":1025}`, statusInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newScanner([]byte(tc.opts))
			var api *apiError
			if !errors.As(err, &api) || api.status != tc.code {
				t.Fatalf("expected status %d, got %v", tc.code, err)
			}
		})
	}
	s := scannerForTest(t, testConfig, map[string]any{"max_findings": 1, "max_input_bytes": 100})
	for _, tc := range []struct {
		input, attrs []byte
		status       int32
	}{
		{[]byte(strings.Repeat("x", 101)), nil, statusLimit},
		{[]byte(testToken + " " + testToken), nil, statusLimit},
		{[]byte{0xff}, nil, statusInvalid},
		{nil, []byte(`[]`), statusInvalid},
		{nil, []byte(`{"path":3}`), statusInvalid},
	} {
		result, err := s.scan(tc.input, tc.attrs)
		var api *apiError
		if result != nil || !errors.As(err, &api) || api.status != tc.status {
			t.Fatalf("expected no partial result and status %d, got %s, %v", tc.status, result, err)
		}
	}
	// Limit errors must not poison reuse of the same scanner.
	if _, err := s.scan([]byte(testToken), nil); err != nil {
		t.Fatal(err)
	}
}

func TestPrefilterAndHandleLifetime(t *testing.T) {
	s := scannerForTest(t, "prefilter = '''attributes[\"path\"] == \"ignored.env\"'''\n"+testConfig, nil)
	encoded, err := s.scan([]byte(testToken), []byte(`{"path":"ignored.env"}`))
	if err != nil {
		t.Fatal(err)
	}
	var response scanResponse
	if err := json.Unmarshal(encoded, &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Findings) != 0 || response.Summary.BytesInspected != 0 {
		t.Fatal("source prefilter was not applied")
	}
	handle, err := registerScanner(s)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := lookupScanner(handle)
	if err != nil || retained != s {
		t.Fatal("registered scanner cannot be retrieved")
	}
	if !deleteScanner(handle) || deleteScanner(handle) {
		t.Fatal("handle deletion must succeed exactly once")
	}
	if _, err := lookupScanner(handle); err == nil {
		t.Fatal("deleted handle remains accessible")
	}
	if _, err := retained.scan([]byte(testToken), []byte(`{"path":"included.env"}`)); err != nil {
		t.Fatalf("in-flight reference invalidated by deletion: %v", err)
	}
}

func TestConcurrentScans(t *testing.T) {
	s := scannerForTest(t, testConfig, nil)
	handle, err := registerScanner(s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteScanner(handle) })
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			for range 25 {
				scanner, err := lookupScanner(handle)
				if err != nil {
					t.Error(err)
					return
				}
				if _, err := scanner.scan([]byte(testToken), nil); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	group.Wait()
}

func TestScanFileUsesFilesystemSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.env")
	cfgPath := filepath.Join(dir, "rules.toml")
	if err := os.WriteFile(cfgPath, []byte(testConfig+"\npath = 'config[.]env$'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	configJSON, err := json.Marshal(scannerOptions{ConfigPath: cfgPath, MaxInputBytes: len(testToken), MaxFindings: 1})
	if err != nil {
		t.Fatal(err)
	}
	s, err := newScanner(configJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(testToken), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := s.scanFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var response scanResponse
	if err := json.Unmarshal(result, &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Findings) != 1 || response.Findings[0].Location.Path != path ||
		response.Summary.BytesInspected != uint64(len(testToken)) {
		t.Fatalf("unexpected file scan: %+v", response)
	}
	for _, tc := range []struct {
		path   string
		status int32
	}{
		{dir, statusInvalid}, {filepath.Join(dir, "missing"), statusScan}, {cfgPath, statusLimit},
	} {
		result, err := s.scanFile(tc.path)
		var api *apiError
		if result != nil || !errors.As(err, &api) || api.status != tc.status {
			t.Fatalf("scanFile(%q) returned %s, %v", tc.path, result, err)
		}
	}
}
