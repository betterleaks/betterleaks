package celenv

import (
	"os"
	"strings"

	"github.com/google/cel-go/common/functions"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// ParseValidationEnvAllowlist converts CLI flag fragments (comma-separated
// within an entry and/or repeated flags) into a set of environment variable
// names. Empty entries are skipped. The result may be empty.
func ParseValidationEnvAllowlist(parts []string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		for _, name := range strings.Split(part, ",") {
			n := strings.TrimSpace(name)
			if n != "" {
				out[n] = struct{}{}
			}
		}
	}
	return out
}

func envBinding(e *ValidationEnvironment) functions.UnaryOp {
	return func(val ref.Val) ref.Val {
		nameVal, ok := val.(types.String)
		if !ok {
			return types.NewErr("env: name must be a string, got %T", val)
		}
		name := string(nameVal)
		if len(e.AllowedEnv) == 0 {
			return types.NewErr("env: no validation env allowlist configured (use --validation-env-vars)")
		}
		if _, ok := e.AllowedEnv[name]; !ok {
			return types.NewErr("env: %q not in validation env allowlist", name)
		}
		return types.String(os.Getenv(name))
	}
}
