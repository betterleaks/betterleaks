package celenv

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/functions"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

func validateBindings() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("validate.unknown",
			cel.Overload("validate_unknown_map",
				[]*cel.Type{cel.MapType(cel.StringType, cel.DynType)},
				cel.MapType(cel.StringType, cel.DynType),
				cel.UnaryBinding(unknownBinding()),
			),
		),
		// Deprecated: use validate.unknown.
		cel.Function("unknown",
			cel.Overload("unknown_map",
				[]*cel.Type{cel.MapType(cel.StringType, cel.DynType)},
				cel.MapType(cel.StringType, cel.DynType),
				cel.UnaryBinding(unknownBinding()),
			),
		),
	}
}

func unknownBinding() functions.UnaryOp {
	return func(val ref.Val) ref.Val {
		m := map[string]any{"result": "unknown"}
		if nativeVal, err := val.ConvertToNative(mapAnyType); err == nil {
			if resp, ok := nativeVal.(map[string]any); ok {
				if status, ok := resp["status"]; ok {
					switch status {
					case int64(429):
						m["reason"] = "rate limited"
					default:
						m["reason"] = fmt.Sprintf("HTTP %v", status)
					}
				}
			}
		}
		return types.DefaultTypeAdapter.NativeToValue(m)
	}
}
