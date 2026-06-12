package celenv

import (
	"os"
	"strings"

	"github.com/google/cel-go/cel"
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

func envBindings(e *ValidationEnvironment) []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("env.get",
			cel.Overload("env_get_string",
				[]*cel.Type{cel.StringType},
				cel.StringType,
				cel.UnaryBinding(envBinding(e)),
			),
		),
		cel.Function("env.getOrDefault",
			cel.Overload("env_get_or_default_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.StringType,
				cel.BinaryBinding(envOrDefaultBinding(e)),
			),
		),
		// Deprecated: use env.get.
		cel.Function("env",
			cel.Overload("env_string",
				[]*cel.Type{cel.StringType},
				cel.StringType,
				cel.UnaryBinding(envBinding(e)),
			),
		),
	}
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

func envOrDefaultBinding(e *ValidationEnvironment) functions.BinaryOp {
	return func(lhs ref.Val, rhs ref.Val) ref.Val {
		nameVal, ok := lhs.(types.String)
		if !ok {
			return types.NewErr("env.getOrDefault: name must be a string, got %T", lhs)
		}
		defaultVal, ok := rhs.(types.String)
		if !ok {
			return types.NewErr("env.getOrDefault: default must be a string, got %T", rhs)
		}

		name := string(nameVal)
		defaultValue := string(defaultVal)
		if len(e.AllowedEnv) == 0 {
			return types.String(defaultValue)
		}
		if _, ok := e.AllowedEnv[name]; !ok {
			return types.String(defaultValue)
		}
		if value, ok := os.LookupEnv(name); ok {
			return types.String(value)
		}
		return types.String(defaultValue)
	}
}
