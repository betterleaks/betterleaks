package exprruntime

import "encoding/base64"

func base64Namespace() map[string]any {
	return map[string]any{
		"encode": base64Encode,
		"decode": base64Decode,
	}
}

func base64Encode(bs []byte) string { return base64.StdEncoding.EncodeToString(bs) }

func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
