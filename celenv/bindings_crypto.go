package celenv

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"fmt"

	"github.com/google/cel-go/common/functions"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

func md5Binding(e *ValidationEnvironment) functions.UnaryOp {
	return func(value ref.Val) ref.Val {
		str, ok := value.(types.String)
		if !ok {
			return types.MaybeNoSuchOverloadErr(value)
		}

		hash := md5.Sum([]byte(str))
		return types.String(fmt.Sprintf("%x", hash))
	}
}

func hmacSha256Binding(e *ValidationEnvironment) functions.BinaryOp {
	return func(lhs ref.Val, rhs ref.Val) ref.Val {
		key, ok := lhs.(types.Bytes)
		if !ok {
			return types.MaybeNoSuchOverloadErr(lhs)
		}
		msg, ok := rhs.(types.Bytes)
		if !ok {
			return types.MaybeNoSuchOverloadErr(rhs)
		}

		h := hmac.New(sha256.New, []byte(key))
		h.Write([]byte(msg))
		return types.Bytes(h.Sum(nil))
	}
}
