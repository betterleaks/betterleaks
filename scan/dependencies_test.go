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
