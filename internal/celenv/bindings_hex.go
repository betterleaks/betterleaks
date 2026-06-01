package celenv

import (
	"encoding/hex"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/functions"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

func hexBindings() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("hex.encode",
			cel.Overload("hex_encode_bytes",
				[]*cel.Type{cel.BytesType},
				cel.StringType,
				cel.UnaryBinding(hexEncodeBinding()),
			),
		),
	}
}

func hexEncodeBinding() functions.UnaryOp {
	return func(value ref.Val) ref.Val {
		bs, ok := value.(types.Bytes)
		if !ok {
			return types.MaybeNoSuchOverloadErr(value)
		}

		return types.String(hex.EncodeToString([]byte(bs)))
	}
}
