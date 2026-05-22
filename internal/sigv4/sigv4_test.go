package sigv4

import (
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeriveSigningKey is the canonical AWS test vector from
// https://docs.aws.amazon.com/IAM/latest/UserGuide/signature-v4-examples.html.
func TestDeriveSigningKey(t *testing.T) {
	got := DeriveSigningKey(
		"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		"20150830", "us-east-1", "iam",
	)
	const want = "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
	assert.Equal(t, want, hex.EncodeToString(got))
}

func TestURIEncode(t *testing.T) {
	cases := []struct {
		in          string
		encodeSlash bool
		want        string
	}{
		{"foo/bar.txt", false, "foo/bar.txt"},
		{"foo/bar.txt", true, "foo%2Fbar.txt"},
		{"hello world", false, "hello%20world"},
		{"a+b=c", false, "a%2Bb%3Dc"},
		{"unicode-café", false, "unicode-caf%C3%A9"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, URIEncode(tc.in, tc.encodeSlash))
		})
	}
}

func TestSign_setsRequiredHeaders(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://mybucket.s3.us-east-1.amazonaws.com/?list-type=2", nil)
	require.NoError(t, err)
	creds := Credentials{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
	require.NoError(t, Sign(req, nil, "us-east-1", "s3", creds))

	auth := req.Header.Get("Authorization")
	assert.Contains(t, auth, Algorithm+" ")
	assert.Contains(t, auth, "Credential=AKIAIOSFODNN7EXAMPLE/")
	assert.Contains(t, auth, "/us-east-1/s3/aws4_request")
	assert.Contains(t, auth, "SignedHeaders=host;x-amz-content-sha256;x-amz-date")
	assert.Equal(t, EmptyPayloadSHA, req.Header.Get("X-Amz-Content-Sha256"))
	assert.NotEmpty(t, req.Header.Get("X-Amz-Date"))
}

func TestSign_includesSessionTokenWhenSet(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.s3.us-east-1.amazonaws.com/", nil)
	require.NoError(t, err)
	creds := Credentials{AccessKey: "ak", SecretKey: "sk", SessionToken: "tok"}
	require.NoError(t, Sign(req, nil, "us-east-1", "s3", creds))
	assert.Equal(t, "tok", req.Header.Get("X-Amz-Security-Token"))
	assert.Contains(t, req.Header.Get("Authorization"), "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token")
}

func TestSign_missingCredsErrors(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.s3.us-east-1.amazonaws.com/", nil)
	require.Error(t, Sign(req, nil, "us-east-1", "s3", Credentials{}))
}

// TestSign_deterministic verifies that signing the same request at the same
// time produces the same Authorization header — a regression guard for any
// future canonicalization changes.
func TestSign_deterministic(t *testing.T) {
	ts := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	mk := func() *http.Request {
		r, _ := http.NewRequest(http.MethodPost, "https://sts.amazonaws.com/", nil)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	creds := Credentials{AccessKey: "AKIDEXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
	r1, r2 := mk(), mk()
	require.NoError(t, signAt(r1, []byte("Action=GetCallerIdentity&Version=2011-06-15"), "us-east-1", "sts", creds, ts))
	require.NoError(t, signAt(r2, []byte("Action=GetCallerIdentity&Version=2011-06-15"), "us-east-1", "sts", creds, ts))
	assert.Equal(t, r1.Header.Get("Authorization"), r2.Header.Get("Authorization"))
	assert.Contains(t, r1.Header.Get("Authorization"), "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date")
}
