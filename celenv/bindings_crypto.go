package celenv

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"strconv"
	"time"

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

func hmacSha256Binding(e *Environment) functions.BinaryOp {
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

func timeNowUnixBinding(e *Environment) functions.FunctionOp {
	return func(args ...ref.Val) ref.Val {
		return types.String(strconv.FormatInt(time.Now().Unix(), 10))
	}
}
