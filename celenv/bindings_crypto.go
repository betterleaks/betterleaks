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

func md5Binding() functions.UnaryOp {
	return func(value ref.Val) ref.Val {
		bs, ok := value.(types.Bytes)
		if !ok {
			return types.MaybeNoSuchOverloadErr(value)
		}

		hash := md5.Sum([]byte(bs))
		return types.Bytes(hash[:])
	}
}

func sha1Binding() functions.UnaryOp {
	return func(value ref.Val) ref.Val {
		bs, ok := value.(types.Bytes)
		if !ok {
			return types.MaybeNoSuchOverloadErr(value)
		}

		hash := sha1.Sum([]byte(bs))
		return types.Bytes(hash[:])
	}
}

func hmacSha256Binding() functions.BinaryOp {
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

// TODO maybe split out to it's own file for encodings?
// encode/decode etc
func hexEncodeBinding() functions.UnaryOp {
	return func(value ref.Val) ref.Val {
		bs, ok := value.(types.Bytes)
		if !ok {
			return types.MaybeNoSuchOverloadErr(value)
		}

		return types.String(hex.EncodeToString([]byte(bs)))
	}
}
