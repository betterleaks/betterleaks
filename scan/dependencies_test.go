package scan_test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestSDKDoesNotImportWASMBackend(t *testing.T) {
	// Inspect production imports, not test imports: engine parity tests opt into
	// RE2, while SDK users must be able to build without its WASM runtime.
	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", "-f", "{{.ImportPath}}",
		".", "../analyze", "../pipeline", "../sources/prefilter")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("list SDK dependencies: %v\n%s", err, output)
	}
	for _, dependency := range strings.Fields(string(output)) {
		for _, forbidden := range []string{"github.com/betterleaks/go-re2", "github.com/tetratelabs/wazero", "github.com/wasilibs/wazero-helpers"} {
			if dependency == forbidden || strings.HasPrefix(dependency, forbidden+"/") {
				t.Errorf("SDK imports optional WASM dependency %s", dependency)
			}
		}
	}
}

func TestSDKDoesNotImportSourceImplementations(t *testing.T) {
	// Include Reader's package and the pipeline/prefilter entry points: making
	// ScanString lightweight must also work for callers scanning their own streams.
	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", "-f", "{{.ImportPath}}",
		".", "../report", "../analyze", "../pipeline", "../sources", "../sources/prefilter", "../sources/scm")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("list SDK dependencies: %v\n%s", err, output)
	}
	const sourcePath = "github.com/betterleaks/betterleaks/v2/sources"
	allowed := map[string]bool{
		sourcePath:                      true,
		sourcePath + "/internal/stream": true,
		sourcePath + "/prefilter":       true,
		sourcePath + "/scm":             true,
	}
	for _, dependency := range strings.Fields(string(output)) {
		if strings.HasPrefix(dependency, sourcePath+"/") && !allowed[dependency] {
			t.Errorf("SDK imports source implementation %s", dependency)
		}
		for _, forbidden := range []string{
			"github.com/go-git/go-git",
			"github.com/mholt/archives",
			"github.com/charlievieth/fastwalk",
		} {
			if dependency == forbidden || strings.HasPrefix(dependency, forbidden+"/") {
				t.Errorf("SDK imports optional source dependency %s", dependency)
			}
		}
	}
}

func TestSourceProtocolDoesNotImportThirdPartyPackages(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}",
		"../sources", "../sources/scm")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("list source protocol dependencies: %v\n%s", err, output)
	}
	for _, dependency := range strings.Fields(string(output)) {
		if !strings.HasPrefix(dependency, "github.com/betterleaks/betterleaks/v2/") {
			t.Errorf("source protocol imports third-party package %s", dependency)
		}
	}
}
