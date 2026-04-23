package celenv

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"

	"github.com/google/cel-go/common/functions"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

func md5Binding(e *Environment) functions.UnaryOp {
	return func(value ref.Val) ref.Val {
		switch v := value.(type) {
		case types.String:
			hash := md5.Sum([]byte(v))
			return types.Bytes(hash[:])
		case types.Bytes:
			hash := md5.Sum([]byte(v))
			return types.Bytes(hash[:])
		default:
			return types.MaybeNoSuchOverloadErr(value)
		}
	}
}

func sha1Binding(e *Environment) functions.UnaryOp {
	return func(value ref.Val) ref.Val {
		bs, ok := value.(types.Bytes)
		if !ok {
			return types.MaybeNoSuchOverloadErr(value)
		}

		hash := sha1.Sum([]byte(bs))
		return types.Bytes(hash[:])
	}
}

func hexEncodeBinding(e *Environment) functions.UnaryOp {
	return func(value ref.Val) ref.Val {
		bs, ok := value.(types.Bytes)
		if !ok {
			return types.MaybeNoSuchOverloadErr(value)
		}

		return types.String(hex.EncodeToString([]byte(bs)))
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
