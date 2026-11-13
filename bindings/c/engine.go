//go:build cgo && betterleaks_ffi

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"unicode/utf8"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/prefilter"
	"github.com/betterleaks/betterleaks/v2/version"
)

const (
	abiVersion         = 1
	statusInvalid      = 1
	statusConfig       = 2
	statusScan         = 3
	statusLimit        = 4
	statusInternal     = 5
	maxOptionsBytes    = 8 << 20
	maxAttributeBytes  = 1 << 20
	maxPathBytes       = 1 << 20
	maxInputBytes      = 64 << 20
	maxResultBytes     = 64 << 20
	maxDetectionBytes  = 64 << 20
	maxCandidates      = 100_000
	maxFragmentBytes   = 128 << 10
	maxMatchIndexBytes = 8 << 20
	maxDecodeDepth     = 32
	defaultInputBytes  = 8 << 20
	defaultFindings    = 10_000
)

type apiError struct {
	status int32
	err    error
}

func (e *apiError) Error() string { return e.err.Error() }
func (e *apiError) Unwrap() error { return e.err }

func failure(status int32, message string) error {
	return &apiError{status: status, err: errors.New(message)}
}

type scannerOptions struct {
	ConfigTOML     *string `json:"config_toml"`
	ConfigPath     string  `json:"config_path"`
	Workers        int     `json:"workers"`
	MaxDecodeDepth int     `json:"max_decode_depth"`
	MaxInputBytes  int     `json:"max_input_bytes"`
	MaxFindings    int     `json:"max_findings"`
}

type nativeScanner struct {
	scanner       *scan.Scanner
	prefilter     sources.PrefilterFunc
	configHash    string
	maxInputBytes int
	maxFindings   int
}

// Only integer IDs cross the ABI. The registry roots Go objects; an in-flight
// call also retains its own reference, independently of concurrent deletion.
var scanners = struct {
	sync.RWMutex
	next   uint64
	values map[uint64]*nativeScanner
}{values: make(map[uint64]*nativeScanner)}

func registerScanner(scanner *nativeScanner) (uint64, error) {
	scanners.Lock()
	defer scanners.Unlock()
	if scanners.next == ^uint64(0) {
		return 0, failure(statusInternal, "scanner handle space exhausted")
	}
	scanners.next++
	scanners.values[scanners.next] = scanner
	return scanners.next, nil
}

func lookupScanner(handle uint64) (*nativeScanner, error) {
	scanners.RLock()
	scanner := scanners.values[handle]
	scanners.RUnlock()
	if scanner == nil {
		return nil, failure(statusInvalid, "invalid scanner handle")
	}
	return scanner, nil
}

func deleteScanner(handle uint64) bool {
	scanners.Lock()
	defer scanners.Unlock()
	if _, ok := scanners.values[handle]; !ok {
		return false
	}
	delete(scanners.values, handle)
	return true
}

func decodeObject(data []byte, value any) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' || !utf8.Valid(data) {
		return errors.New("expected a UTF-8 JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("unexpected data after JSON object")
	}
	return nil
}

func newScanner(data []byte) (*nativeScanner, error) {
	options := scannerOptions{MaxInputBytes: defaultInputBytes, MaxFindings: defaultFindings}
	if len(data) > 0 {
		if err := decodeObject(data, &options); err != nil {
			return nil, &apiError{statusInvalid, fmt.Errorf("scanner options: %w", err)}
		}
	}
	if options.MaxInputBytes < 1 || options.MaxInputBytes > maxInputBytes {
		return nil, failure(statusInvalid, "max_input_bytes must be between 1 and 67108864")
	}
	if options.MaxFindings < 1 || options.MaxFindings > 100_000 {
		return nil, failure(statusInvalid, "max_findings must be between 1 and 100000")
	}
	if options.Workers < 0 {
		return nil, failure(statusInvalid, "workers must be non-negative")
	}
	if options.MaxDecodeDepth < 0 || options.MaxDecodeDepth > maxDecodeDepth {
		return nil, failure(statusInvalid, "max_decode_depth must be between 0 and 32")
	}
	if options.ConfigTOML == nil && options.ConfigPath != "" {
		return nil, failure(statusInvalid, "config_path requires config_toml")
	}
	var cfg *config.Config
	var err error
	if options.ConfigTOML == nil {
		cfg, err = config.Default()
	} else {
		cfg, err = config.ParseTOMLString(*options.ConfigTOML, options.ConfigPath)
	}
	if err != nil {
		return nil, &apiError{statusConfig, err}
	}
	skip, err := prefilter.Compile(cfg.PrefilterExpr, prefilter.Options{})
	if err != nil {
		return nil, &apiError{statusConfig, err}
	}
	scanner, err := scan.New(cfg, scan.WithPrecompile(), scan.WithWorkers(options.Workers),
		scan.WithMaxDecodeDepth(options.MaxDecodeDepth))
	if err != nil {
		return nil, &apiError{statusConfig, err}
	}
	return &nativeScanner{scanner, skip, cfg.Hash(), options.MaxInputBytes, options.MaxFindings}, nil
}

type scanSummary struct {
	BytesInspected uint64 `json:"bytes_inspected"`
	Findings       int    `json:"findings"`
}

type scanResponse struct {
	SchemaVersion int              `json:"schema_version"`
	EngineVersion string           `json:"engine_version"`
	ConfigHash    string           `json:"config_hash"`
	Findings      []report.Finding `json:"findings"`
	Summary       scanSummary      `json:"summary"`
}

func (s *nativeScanner) scan(input, attributeJSON []byte) ([]byte, error) {
	if len(input) > s.maxInputBytes {
		return nil, failure(statusLimit, "input exceeds max_input_bytes")
	}
	if !utf8.Valid(input) {
		return nil, failure(statusInvalid, "input must be valid UTF-8")
	}
	attributes, err := sourceAttributes(attributeJSON)
	if err != nil {
		return nil, err
	}
	return s.scanReader(bytes.NewReader(input), attributes)
}

func sourceAttributes(attributeJSON []byte) (map[string]string, error) {
	if len(attributeJSON) > maxAttributeBytes {
		return nil, failure(statusLimit, "source attributes exceed 1 MiB")
	}
	attributes := map[string]string{}
	if len(attributeJSON) > 0 {
		if err := decodeObject(attributeJSON, &attributes); err != nil {
			return nil, &apiError{statusInvalid, fmt.Errorf("source attributes: %w", err)}
		}
	}
	return attributes, nil
}

func (s *nativeScanner) scanReader(content io.Reader, attributes map[string]string) ([]byte, error) {
	return s.scanSource(&sources.Reader{
		Content: content, Attributes: attributes, Prefilter: s.prefilter,
	})
}

// Both entry points use the same per-call detection and output budgets.
func (s *nativeScanner) scanSource(source sources.Source) ([]byte, error) {
	response := scanResponse{
		SchemaVersion: abiVersion,
		EngineVersion: version.Version,
		ConfigHash:    s.configHash,
		Findings:      []report.Finding{},
	}
	// Budget the serialized size while findings accumulate; a permissive
	// max_findings must not allocate an oversized response before the final
	// size check. Marshaling findings twice only costs on finding-heavy scans.
	resultBytes := 0
	limits := scan.ScanLimits{
		MaxFindings: s.maxFindings, MaxCandidates: maxCandidates,
		MaxBytes: maxDetectionBytes, MaxFragmentBytes: maxFragmentBytes,
		MaxMatchIndexBytes: maxMatchIndexBytes,
	}
	summary, err := s.scanner.ScanWithLimits(context.Background(), source, limits, func(finding report.Finding) error {
		if len(response.Findings) == s.maxFindings {
			return failure(statusLimit, "scan exceeds max_findings")
		}
		encoded, err := json.Marshal(finding)
		if err != nil {
			return &apiError{statusInternal, err}
		}
		if resultBytes += len(encoded) + 1; resultBytes > maxResultBytes {
			return failure(statusLimit, "serialized results exceed 64 MiB")
		}
		response.Findings = append(response.Findings, finding)
		return nil
	})
	if err != nil {
		if errors.Is(err, scan.ErrLimitExceeded) {
			return nil, &apiError{statusLimit, err}
		}
		var api *apiError
		if errors.As(err, &api) {
			return nil, api
		}
		return nil, &apiError{statusScan, err}
	}
	response.Summary = scanSummary{summary.BytesInspected, summary.Findings}
	encoded, err := json.Marshal(response)
	if err != nil {
		return nil, &apiError{statusInternal, err}
	}
	if len(encoded) > maxResultBytes {
		return nil, failure(statusLimit, "serialized results exceed 64 MiB")
	}
	return encoded, nil
}
