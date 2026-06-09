package celenv

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/functions"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

func cryptoBindings() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("crypto.md5",
			cel.Overload("crypto_md5_bytes",
				[]*cel.Type{cel.BytesType},
				cel.BytesType,
				cel.UnaryBinding(md5Binding()),
			),
		),
		cel.Function("crypto.sha1",
			cel.Overload("crypto_sha1_bytes",
				[]*cel.Type{cel.BytesType},
				cel.BytesType,
				cel.UnaryBinding(sha1Binding()),
			),
		),
		cel.Function("crypto.hmacSha256",
			cel.Overload("crypto_hmac_sha256_camel_bytes_bytes",
				[]*cel.Type{cel.BytesType, cel.BytesType},
				cel.BytesType,
				cel.BinaryBinding(hmacSha256Binding()),
			),
		),
		cel.Function("crypto.hmacSha1",
			cel.Overload("crypto_hmac_sha1_camel_bytes_bytes",
				[]*cel.Type{cel.BytesType, cel.BytesType},
				cel.BytesType,
				cel.BinaryBinding(hmacSha1Binding()),
			),
		),
		// Deprecated: use crypto.hmacSha256.
		cel.Function("crypto.hmac_sha256",
			cel.Overload("crypto_hmac_sha256_bytes_bytes",
				[]*cel.Type{cel.BytesType, cel.BytesType},
				cel.BytesType,
				cel.BinaryBinding(hmacSha256Binding()),
			),
		),
	}
}

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

func hmacSha1Binding() functions.BinaryOp {
	return func(lhs ref.Val, rhs ref.Val) ref.Val {
		key, ok := lhs.(types.Bytes)
		if !ok {
			return types.MaybeNoSuchOverloadErr(lhs)
		}
		msg, ok := rhs.(types.Bytes)
		if !ok {
			return types.MaybeNoSuchOverloadErr(rhs)
		}

		h := hmac.New(sha1.New, []byte(key))
		h.Write([]byte(msg))
		return types.Bytes(h.Sum(nil))
	}
}
