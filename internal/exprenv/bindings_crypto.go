package exprenv

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
)

func cryptoNamespace() map[string]any {
	return map[string]any{
		"md5":         md5Bytes,
		"sha1":        sha1Bytes,
		"hmacSha1":    hmacSha1Bytes,
		"hmacSha256":  hmacSha256Bytes,
		"hmac_sha256": hmacSha256Bytes,
	}
}

func md5Bytes(bs []byte) []byte {
	hash := md5.Sum(bs)
	return hash[:]
}

func sha1Bytes(bs []byte) []byte {
	hash := sha1.Sum(bs)
	return hash[:]
}

func hmacSha256Bytes(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(msg)
	return h.Sum(nil)
}

func hmacSha1Bytes(key, msg []byte) []byte {
	h := hmac.New(sha1.New, key)
	_, _ = h.Write(msg)
	return h.Sum(nil)
}
