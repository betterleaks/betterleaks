package celenv

import (
	"crypto/md5"
	"fmt"

	"github.com/google/cel-go/common/functions"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

func md5Binding(e *Environment) functions.UnaryOp {
	return func(value ref.Val) ref.Val {
		str, ok := value.(types.String)
		if !ok {
			return types.MaybeNoSuchOverloadErr(value)
		}

		hash := md5.Sum([]byte(str))
		return types.String(fmt.Sprintf("%x", hash))
	}
}
