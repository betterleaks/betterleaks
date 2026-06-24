package exprenv

import "encoding/hex"

func hexNamespace() map[string]any {
	return map[string]any{
		"encode": hexEncode,
	}
}

func hexEncode(bs []byte) string { return hex.EncodeToString(bs) }
