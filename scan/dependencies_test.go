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

func TestScanDoesNotImportSourceImplementations(t *testing.T) {
	// Scanning strings must not compile in the git, archive and file-walking source
	// implementations. scan and report take their shared types from sources/sourcetypes
	// and sources/scm/platform instead of sources and sources/scm.
	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", "-f", "{{.ImportPath}}", ".", "../report")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("list scan dependencies: %v\n%s", err, output)
	}
	allowed := map[string]bool{
		"github.com/betterleaks/betterleaks/v2/sources/sourcetypes":  true,
		"github.com/betterleaks/betterleaks/v2/sources/scm/platform": true,
	}
	for _, dependency := range strings.Fields(string(output)) {
		if allowed[dependency] {
			continue
		}
		for _, forbidden := range []string{
			"github.com/go-git/go-git",
			"github.com/mholt/archives",
			"github.com/charlievieth/fastwalk",
			"github.com/betterleaks/betterleaks/v2/sources",
		} {
			if dependency == forbidden || strings.HasPrefix(dependency, forbidden+"/") {
				t.Errorf("scan imports source implementation %s", dependency)
			}
		}
	}
}
