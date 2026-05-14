package celenv

import (
	"encoding/json"

	"github.com/google/cel-go/common/functions"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// jsonStringBinding returns a JSON-encoded string value: double quotes,
// RFC 8259 escapes (newlines as \n, quotes as \", etc.). Use when embedding
// arbitrary text inside a hand-built JSON request body; raw newlines inside
// string literals make JSON invalid and APIs return 400.
func jsonStringBinding() functions.UnaryOp {
	return func(val ref.Val) ref.Val {
		s, ok := val.(types.String)
		if !ok {
			return types.NewErr("json.string: argument must be a string, got %T", val)
		}
		b, err := json.Marshal(string(s))
		if err != nil {
			return types.NewErr("json.string: %v", err)
		}
		return types.String(string(b))
	}
}
