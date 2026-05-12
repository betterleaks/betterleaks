// Package sigv4 implements AWS Signature Version 4 request signing.
//
// SigV4 is the request-signing scheme used by S3, STS, and every S3-compatible
// object store (R2, MinIO, B2, etc.). The algorithm and credentials are
// per-service: the signing math is identical, but credentials issued by one
// provider only authenticate against that provider's endpoints.
//
// Spec: https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	Algorithm = "AWS4-HMAC-SHA256"
	// EmptyPayloadSHA is the lowercase-hex SHA-256 of the empty string, used
	// as the canonical payload hash for requests with no body.
	EmptyPayloadSHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// Credentials are static SigV4 credentials. SessionToken is optional and only
// populated for temporary credentials (STS, IAM Roles Anywhere, etc.).
type Credentials struct {
	AccessKey    string
	SecretKey    string
	SessionToken string
}

// Sign signs req in place using SigV4 for the given region and service.
//
// The host is taken from req.Host (falling back to req.URL.Host). The body
// parameter is hashed for the canonical-payload component; pass nil for empty
// bodies. X-Amz-Date, X-Amz-Content-Sha256, and Authorization headers are set
// on the request; X-Amz-Security-Token is set when creds.SessionToken is
// non-empty.
//
// Headers included in the signed-headers set: host, x-amz-*, content-*. Other
// headers (Accept-Encoding, User-Agent, etc.) are intentionally excluded so
// the signature isn't invalidated by middleware that mutates them.
func Sign(req *http.Request, body []byte, region, service string, creds Credentials) error {
	return signAt(req, body, region, service, creds, time.Now().UTC())
}

// signAt is Sign with an injected timestamp (for testing).
func signAt(req *http.Request, body []byte, region, service string, creds Credentials, now time.Time) error {
	if creds.AccessKey == "" || creds.SecretKey == "" {
		return errors.New("sigv4: missing access key or secret")
	}
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	var payloadHash string
	if len(body) == 0 {
		payloadHash = EmptyPayloadSHA
	} else {
		payloadHash = SHA256Hex(body)
	}

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}

	canonicalHeaders, signedHeaders := canonicalHeaders(req)
	canonicalQuery := canonicalQuery(req.URL.Query())
	canonicalURI := canonicalURI(req.URL.Path)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	stringToSign := strings.Join([]string{
		Algorithm,
		amzDate,
		scope,
		SHA256Hex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := DeriveSigningKey(creds.SecretKey, dateStamp, region, service)
	signature := hex.EncodeToString(HMACSHA256(signingKey, []byte(stringToSign)))

	req.Header.Set("Authorization", fmt.Sprintf(
		"%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		Algorithm, creds.AccessKey, scope, signedHeaders, signature,
	))
	return nil
}

// DeriveSigningKey returns the SigV4 signing key for the given secret, date
// (YYYYMMDD), region, and service.
func DeriveSigningKey(secret, dateStamp, region, service string) []byte {
	kDate := HMACSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := HMACSHA256(kDate, []byte(region))
	kService := HMACSHA256(kRegion, []byte(service))
	return HMACSHA256(kService, []byte("aws4_request"))
}

// HMACSHA256 returns HMAC-SHA256(data) keyed with key.
func HMACSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// SHA256Hex returns the lowercase-hex SHA-256 hash of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func canonicalHeaders(req *http.Request) (canonical, signed string) {
	type kv struct{ k, v string }
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	headers := []kv{{"host", host}}
	for name, values := range req.Header {
		lower := strings.ToLower(name)
		if lower == "host" || lower == "authorization" {
			continue
		}
		// Sign only the headers SigV4 callers tend to set deliberately. Skipping
		// Accept-Encoding/User-Agent etc. avoids signature invalidation when
		// the http.Client populates them later.
		if !strings.HasPrefix(lower, "x-amz-") && !strings.HasPrefix(lower, "content-") {
			continue
		}
		headers = append(headers, kv{lower, strings.Join(values, ",")})
	}
	sort.Slice(headers, func(i, j int) bool { return headers[i].k < headers[j].k })

	var cb, sb strings.Builder
	for i, h := range headers {
		cb.WriteString(h.k)
		cb.WriteByte(':')
		cb.WriteString(strings.TrimSpace(collapseWhitespace(h.v)))
		cb.WriteByte('\n')
		if i > 0 {
			sb.WriteByte(';')
		}
		sb.WriteString(h.k)
	}
	return cb.String(), sb.String()
}

// collapseWhitespace converts runs of spaces/tabs in a header value into a
// single space, as required by the SigV4 canonicalization rules.
func collapseWhitespace(s string) string {
	var b strings.Builder
	var prevSpace bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		prevSpace = false
		b.WriteByte(c)
	}
	return b.String()
}

func canonicalQuery(values map[string][]string) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		vs := values[k]
		sort.Strings(vs)
		for j, v := range vs {
			if i > 0 || j > 0 {
				b.WriteByte('&')
			}
			b.WriteString(URIEncode(k, true))
			b.WriteByte('=')
			b.WriteString(URIEncode(v, true))
		}
	}
	return b.String()
}

// canonicalURI URI-encodes the path once (S3-style; "/" preserved between
// segments). AWS services other than S3 encode twice; S3 is the practical
// caller here and the discrepancy hasn't yet caused issues for STS.
func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	return URIEncode(path, false)
}

// URIEncode applies the AWS-spec URI encoding: unreserved chars
// (A-Z, a-z, 0-9, '-', '_', '.', '~') pass through; everything else is
// percent-encoded. With encodeSlash=false (used for path components), '/' is
// preserved.
func URIEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'),
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
