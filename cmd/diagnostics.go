package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"strings"

	"github.com/betterleaks/betterleaks/v2/internal/ruletiming"
)

const defaultDiagnosticsDir = "diagnostics"

// DiagnosticsManager manages various types of diagnostics
type DiagnosticsManager struct {
	Enabled      bool
	DiagTypes    []string
	OutputDir    string
	cpuProfile   *os.File
	memProfile   string
	traceProfile *os.File
	ruleTimings  *ruletiming.Collector
	logger       *slog.Logger
}

// NewDiagnosticsManager creates a new DiagnosticsManager instance
func NewDiagnosticsManager(diagnosticsFlag string, diagnosticsDir string, logger *slog.Logger) (*DiagnosticsManager, error) {
	if logger == nil {
		logger = discardLogger
	}
	if diagnosticsFlag == "" {
		return &DiagnosticsManager{Enabled: false, logger: logger}, nil
	}

	dm := &DiagnosticsManager{
		Enabled:   true,
		DiagTypes: strings.Split(diagnosticsFlag, ","),
		OutputDir: diagnosticsDir,
		logger:    logger,
	}

	if diagnosticsFlag == "http" {
		if len(diagnosticsDir) != 0 {
			return nil, errors.New("the diagnostics directory should not be set in http mode")
		}

		return dm, nil
	}

	// If no output directory is specified, use the default diagnostics directory.
	if dm.OutputDir == "" {
		dm.OutputDir = defaultDiagnosticsDir
		dm.logger.Debug("No diagnostics directory specified, using default directory", "path", dm.OutputDir)
	}

	// Create the output directory if it doesn't exist
	if err := os.MkdirAll(dm.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create diagnostics directory: %w", err)
	}

	// Make sure the output directory is absolute
	if !filepath.IsAbs(dm.OutputDir) {
		absPath, err := filepath.Abs(dm.OutputDir)
		if err != nil {
			return nil, fmt.Errorf("failed to get absolute path for diagnostics directory: %w", err)
		}
		dm.OutputDir = absPath
	}

	if dm.HasDiagType("rules") {
		dm.ruleTimings = ruletiming.NewCollector()
	}

	dm.logger.Debug("Diagnostics enabled", "types", strings.Join(dm.DiagTypes, ","))
	dm.logger.Debug("Diagnostics output directory", "path", dm.OutputDir)

	return dm, nil
}

// StartDiagnostics starts all enabled diagnostics
func (dm *DiagnosticsManager) StartDiagnostics() error {
	if !dm.Enabled {
		return nil
	}

	var err error

	for _, diagType := range dm.DiagTypes {
		diagType = strings.TrimSpace(diagType)
		switch diagType {
		case "cpu":
			if err = dm.StartCPUProfile(); err != nil {
				return err
			}
		case "mem":
			if err = dm.SetupMemoryProfile(); err != nil {
				return err
			}
		case "trace":
			if err = dm.StartTraceProfile(); err != nil {
				return err
			}
		case "rules":
		case "http":
			if err = dm.StartHttpHandler(); err != nil {
				return err
			}
		default:
			dm.logger.Warn("Unknown diagnostics type", "type", diagType)
		}
	}

	return nil
}

// StopDiagnostics stops all started diagnostics
func (dm *DiagnosticsManager) StopDiagnostics() {
	if !dm.Enabled {
		return
	}

	dm.logger.Debug("Stopping diagnostics and writing profiling data...")

	for _, diagType := range dm.DiagTypes {
		diagType = strings.TrimSpace(diagType)
		switch diagType {
		case "cpu":
			dm.StopCPUProfile()
		case "mem":
			dm.WriteMemoryProfile()
		case "trace":
			dm.StopTraceProfile()
		case "rules":
			if err := dm.writeRuleTimings(); err != nil {
				dm.logger.Error("Could not write rule timing diagnostics", "error", err)
			}
		case "http":
			// No need to stop the http one
		}
	}
}

func (dm *DiagnosticsManager) HasDiagType(want string) bool {
	for _, diagType := range dm.DiagTypes {
		if strings.TrimSpace(diagType) == want {
			return true
		}
	}
	return false
}

func (dm *DiagnosticsManager) StartHttpHandler() error {
	if len(dm.DiagTypes) > 1 {
		return errors.New("other diagnostics modes should not be enabled when http mode is enabled")
	}

	go func() {
		if err := http.ListenAndServe("localhost:6060", nil); err != nil {
			dm.logger.Error("Diagnostics server stopped", "error", err)
		}
	}()

	dm.logger.Info("Diagnostics server started", "url", "http://localhost:6060/debug/pprof/")
	return nil
}

// StartCPUProfile starts CPU profiling
func (dm *DiagnosticsManager) StartCPUProfile() error {
	cpuProfilePath := filepath.Join(dm.OutputDir, "cpu.pprof")
	f, err := os.Create(cpuProfilePath)
	if err != nil {
		return fmt.Errorf("could not create CPU profile at %s: %w", cpuProfilePath, err)
	}

	if err := pprof.StartCPUProfile(f); err != nil {
		_ = f.Close()
		return fmt.Errorf("could not start CPU profile: %w", err)
	}

	dm.cpuProfile = f
	return nil
}

// StopCPUProfile stops CPU profiling
func (dm *DiagnosticsManager) StopCPUProfile() {
	if dm.cpuProfile != nil {
		pprof.StopCPUProfile()
		if err := dm.cpuProfile.Close(); err != nil {
			dm.logger.Error("Error closing CPU profile file", "error", err)
		}
		dm.logger.Info("CPU profile written", "path", dm.cpuProfile.Name())
		dm.cpuProfile = nil
	}
}

// SetupMemoryProfile sets up memory profiling to be written when StopDiagnostics is called
func (dm *DiagnosticsManager) SetupMemoryProfile() error {
	memProfilePath := filepath.Join(dm.OutputDir, "mem.pprof")
	dm.memProfile = memProfilePath
	return nil
}

// WriteMemoryProfile writes the memory profile to disk
func (dm *DiagnosticsManager) WriteMemoryProfile() {
	if dm.memProfile == "" {
		return
	}

	f, err := os.Create(dm.memProfile)
	if err != nil {
		dm.logger.Error("Could not create memory profile", "error", err, "path", dm.memProfile)
		return
	}

	// Get memory profile
	runtime.GC() // Run GC before taking the memory profile
	if err := pprof.WriteHeapProfile(f); err != nil {
		dm.logger.Error("Could not write memory profile", "error", err)
	} else {
		dm.logger.Info("Memory profile written", "path", dm.memProfile)
	}

	if err := f.Close(); err != nil {
		dm.logger.Error("Error closing memory profile file", "error", err)
	}

	dm.memProfile = ""
}

// StartTraceProfile starts execution tracing
func (dm *DiagnosticsManager) StartTraceProfile() error {
	traceProfilePath := filepath.Join(dm.OutputDir, "trace.out")
	f, err := os.Create(traceProfilePath)
	if err != nil {
		return fmt.Errorf("could not create trace profile at %s: %w", traceProfilePath, err)
	}

	if err := trace.Start(f); err != nil {
		_ = f.Close()
		return fmt.Errorf("could not start trace profile: %w", err)
	}

	dm.traceProfile = f
	return nil
}

// StopTraceProfile stops execution tracing
func (dm *DiagnosticsManager) StopTraceProfile() {
	if dm.traceProfile != nil {
		trace.Stop()
		if err := dm.traceProfile.Close(); err != nil {
			dm.logger.Error("Error closing trace profile file", "error", err)
		}
		dm.logger.Info("Trace profile written", "path", dm.traceProfile.Name())
		dm.traceProfile = nil
	}
}

func (dm *DiagnosticsManager) withContext(ctx context.Context) context.Context {
	return ruletiming.WithCollector(ctx, dm.ruleTimings)
}

func (dm *DiagnosticsManager) writeRuleTimings() error {
	if dm.ruleTimings == nil {
		return nil
	}

	path := filepath.Join(dm.OutputDir, "rule-timings.txt")
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("could not create rule timing diagnostics at %s: %w", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			dm.logger.Error("Error closing rule timing diagnostics file", "error", err)
		}
	}()

	if err := ruletiming.WriteHuman(f, dm.ruleTimings.Snapshot()); err != nil {
		return fmt.Errorf("could not write rule timing diagnostics: %w", err)
	}
	dm.logger.Info("Rule timing diagnostics written", "path", path)
	return nil
}
