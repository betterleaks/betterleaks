package sources

import (
	"context"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestS3ParseURL(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		want      s3Target
		expectErr bool
	}{
		{
			name: "s3 scheme bucket only",
			raw:  "s3://my-bucket",
			want: s3Target{
				Scheme: "https", Host: "my-bucket.s3.amazonaws.com",
				Bucket: "my-bucket", Prefix: "",
				IsAWS: true, RequiresProbe: true,
				Endpoint: "s3.amazonaws.com",
			},
		},
		{
			name: "s3 scheme bucket with prefix",
			raw:  "s3://my-bucket/logs/2024",
			want: s3Target{
				Scheme: "https", Host: "my-bucket.s3.amazonaws.com",
				Bucket: "my-bucket", Prefix: "logs/2024",
				IsAWS: true, RequiresProbe: true,
				Endpoint: "s3.amazonaws.com",
			},
		},
		{
			name: "virtual-hosted no region",
			raw:  "https://my-bucket.s3.amazonaws.com/foo/",
			want: s3Target{
				Scheme: "https", Host: "my-bucket.s3.amazonaws.com",
				Bucket: "my-bucket", Prefix: "foo/",
				IsAWS: true, RequiresProbe: true,
				Endpoint: "my-bucket.s3.amazonaws.com",
			},
		},
		{
			name: "virtual-hosted with region",
			raw:  "https://my-bucket.s3.us-west-2.amazonaws.com/foo",
			want: s3Target{
				Scheme: "https", Host: "my-bucket.s3.us-west-2.amazonaws.com",
				Bucket: "my-bucket", Prefix: "foo",
				Region: "us-west-2", IsAWS: true,
				Endpoint: "my-bucket.s3.us-west-2.amazonaws.com",
			},
		},
		{
			name: "path-style with region",
			raw:  "https://s3.us-east-1.amazonaws.com/mybucket/x/y",
			want: s3Target{
				Scheme: "https", Host: "s3.us-east-1.amazonaws.com",
				Bucket: "mybucket", Prefix: "x/y",
				Region: "us-east-1", PathStyle: true, IsAWS: true,
				Endpoint: "s3.us-east-1.amazonaws.com",
			},
		},
		{
			name: "path-style legacy global endpoint",
			raw:  "https://s3.amazonaws.com/mybucket/x",
			want: s3Target{
				Scheme: "https", Host: "s3.amazonaws.com",
				Bucket: "mybucket", Prefix: "x",
				PathStyle: true, IsAWS: true, RequiresProbe: true,
				Endpoint: "s3.amazonaws.com",
			},
		},
		{
			name: "r2 virtual-hosted",
			raw:  "https://mybucket.acct123.r2.cloudflarestorage.com/some/prefix",
			want: s3Target{
				Scheme: "https", Host: "mybucket.acct123.r2.cloudflarestorage.com",
				Bucket: "mybucket", Prefix: "some/prefix",
				Region: "auto", Endpoint: "mybucket.acct123.r2.cloudflarestorage.com",
			},
		},
		{
			name: "r2 path-style",
			raw:  "https://acct123.r2.cloudflarestorage.com/mybucket/x",
			want: s3Target{
				Scheme: "https", Host: "acct123.r2.cloudflarestorage.com",
				Bucket: "mybucket", Prefix: "x",
				Region: "auto", PathStyle: true,
				Endpoint: "acct123.r2.cloudflarestorage.com",
			},
		},
		{
			name: "generic minio with port",
			raw:  "http://localhost:9000/mybucket/prefix",
			want: s3Target{
				Scheme: "http", Host: "localhost:9000",
				Bucket: "mybucket", Prefix: "prefix",
				PathStyle: true, Endpoint: "localhost:9000",
			},
		},
		{
			name: "bucket with dots virtual-hosted",
			raw:  "https://bucket.with.dots.s3.amazonaws.com/",
			want: s3Target{
				Scheme: "https", Host: "bucket.with.dots.s3.amazonaws.com",
				Bucket: "bucket.with.dots", Prefix: "",
				IsAWS: true, RequiresProbe: true,
				Endpoint: "bucket.with.dots.s3.amazonaws.com",
			},
		},
		{name: "empty s3 host", raw: "s3:///foo", expectErr: true},
		{name: "path-style no bucket", raw: "https://s3.us-west-2.amazonaws.com/", expectErr: true},
		{name: "generic no bucket", raw: "https://example.com/", expectErr: true},
		{name: "bad scheme", raw: "ftp://host/bucket", expectErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s3ParseURL(tc.raw)
			if tc.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestS3DeriveSigningKey checks the SigV4 key derivation against AWS's published
// example (https://docs.aws.amazon.com/IAM/latest/UserGuide/signature-v4-examples.html).
func TestS3DeriveSigningKey(t *testing.T) {
	got := s3DeriveSigningKey(
		"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		"20150830", "us-east-1", "iam",
	)
	const want = "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
	assert.Equal(t, want, hex.EncodeToString(got))
}

func TestS3URIEncode(t *testing.T) {
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
			assert.Equal(t, tc.want, s3URIEncode(tc.in, tc.encodeSlash))
		})
	}
}

func TestS3Sign_producesExpectedAuthorizationStructure(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://mybucket.s3.us-east-1.amazonaws.com/?list-type=2", nil)
	require.NoError(t, err)
	creds := s3Creds{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
	require.NoError(t, s3Sign(req, nil, "us-east-1", creds))

	auth := req.Header.Get("Authorization")
	require.True(t, strings.HasPrefix(auth, s3SignAlgorithm+" "), "auth prefix: %q", auth)
	require.Contains(t, auth, "Credential=AKIAIOSFODNN7EXAMPLE/")
	require.Contains(t, auth, "/us-east-1/s3/aws4_request")
	require.Contains(t, auth, "SignedHeaders=")
	require.Contains(t, auth, "Signature=")
	require.Equal(t, s3EmptyPayloadSHA256, req.Header.Get("X-Amz-Content-Sha256"))
	require.NotEmpty(t, req.Header.Get("X-Amz-Date"))
}

func TestS3Sign_anonymousSkipsSigning(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://b.s3.amazonaws.com/", nil)
	require.NoError(t, err)
	require.NoError(t, s3Sign(req, nil, "us-east-1", s3Creds{Anonymous: true}))
	assert.Empty(t, req.Header.Get("Authorization"))
	assert.Empty(t, req.Header.Get("X-Amz-Date"))
}

func TestS3_resolveCreds(t *testing.T) {
	t.Run("anonymous", func(t *testing.T) {
		s := &S3{Anonymous: true}
		c, err := s.resolveCreds()
		require.NoError(t, err)
		assert.True(t, c.Anonymous)
	})
	t.Run("explicit", func(t *testing.T) {
		s := &S3{AccessKey: "ak", SecretKey: "sk", SessionToken: "tok"}
		c, err := s.resolveCreds()
		require.NoError(t, err)
		assert.Equal(t, s3Creds{AccessKey: "ak", SecretKey: "sk", SessionToken: "tok"}, c)
	})
	t.Run("env", func(t *testing.T) {
		t.Setenv("AWS_ACCESS_KEY_ID", "envak")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "envsk")
		t.Setenv("AWS_SESSION_TOKEN", "envtok")
		s := &S3{}
		c, err := s.resolveCreds()
		require.NoError(t, err)
		assert.Equal(t, s3Creds{AccessKey: "envak", SecretKey: "envsk", SessionToken: "envtok"}, c)
	})
	t.Run("none fails loud", func(t *testing.T) {
		t.Setenv("AWS_ACCESS_KEY_ID", "")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "")
		s := &S3{}
		_, err := s.resolveCreds()
		require.Error(t, err)
	})
}

func TestS3_skipReason(t *testing.T) {
	s := &S3{}
	const max = 100
	cases := []struct {
		name string
		obj  s3Object
		want string
	}{
		{"glacier", s3Object{Key: "k", Size: 10, StorageClass: s3StorageClassGlacier}, "storage_class:GLACIER"},
		{"deep archive", s3Object{Key: "k", Size: 10, StorageClass: s3StorageClassDeepArchive}, "storage_class:DEEP_ARCHIVE"},
		{"over max", s3Object{Key: "k", Size: 200}, "size_limit"},
		{"empty", s3Object{Key: "k", Size: 0}, "empty"},
		{"directory marker", s3Object{Key: "logs/", Size: 10}, "directory"},
		{"normal object", s3Object{Key: "logs/x.txt", Size: 10, StorageClass: "STANDARD"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, s.skipReason(tc.obj, max))
		})
	}
}

// TestS3_listsAndScans_endToEnd points the source at an httptest server that
// behaves like a minimal S3-compatible endpoint with two list pages and two
// scannable objects.
func TestS3_listsAndScans_endToEnd(t *testing.T) {
	objects := map[string]string{
		"a.txt": "alpha-content",
		"b.txt": "AKIAIOSFODNN7EXAMPLE bravo-content", // contains an AWS-key-shaped string
	}

	page1 := s3ListBucketResult{
		Name: "mybucket", KeyCount: 1, MaxKeys: 1, IsTruncated: true,
		NextContinuationToken: "tok1",
		Contents: []s3Object{
			{Key: "a.txt", Size: int64(len(objects["a.txt"])), ETag: `"etag-a"`, LastModified: "2024-01-01T00:00:00Z", StorageClass: "STANDARD"},
		},
	}
	page2 := s3ListBucketResult{
		Name: "mybucket", KeyCount: 1, MaxKeys: 1, IsTruncated: false,
		Contents: []s3Object{
			{Key: "b.txt", Size: int64(len(objects["b.txt"])), ETag: `"etag-b"`, LastModified: "2024-01-02T00:00:00Z", StorageClass: "STANDARD"},
		},
	}

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every request must be signed.
		require.NotEmpty(t, r.Header.Get("Authorization"), "missing auth on %s %s", r.Method, r.URL)

		if r.URL.Query().Get("list-type") == "2" {
			w.Header().Set("Content-Type", "application/xml")
			if r.URL.Query().Get("continuation-token") == "tok1" {
				require.NoError(t, xml.NewEncoder(w).Encode(page2))
				return
			}
			require.NoError(t, xml.NewEncoder(w).Encode(page1))
			return
		}
		// GET object: path is "/<bucket>/<key>" for path-style.
		// strip "/mybucket/"
		key := strings.TrimPrefix(r.URL.Path, "/mybucket/")
		body, ok := objects[key]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	s := &S3{
		URL:       fmt.Sprintf("%s/mybucket/", srv.URL),
		Region:    "us-east-1",
		AccessKey: "AKIAIOSFODNN7EXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	}
	require.NoError(t, s.Validate())
	assert.Equal(t, "mybucket", s.parsed.Bucket)
	assert.True(t, s.parsed.PathStyle)
	assert.Equal(t, u.Host, s.parsed.Host)

	var mu sync.Mutex
	var keys []string
	attrsByKey := map[string]map[string]string{}
	err := s.Fragments(context.Background(), func(f Fragment, err error) error {
		require.NoError(t, err)
		mu.Lock()
		defer mu.Unlock()
		key := f.Attr(AttrS3Key)
		keys = append(keys, key)
		attrsByKey[key] = f.Attributes
		return nil
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"a.txt", "b.txt"}, keys)

	for _, k := range []string{"a.txt", "b.txt"} {
		a := attrsByKey[k]
		assert.Equal(t, "mybucket", a[AttrS3Bucket])
		assert.Equal(t, "us-east-1", a[AttrS3Region])
		assert.Equal(t, "s3.object", a[AttrResource])
		assert.Equal(t, k, a[AttrPath])
		assert.NotEmpty(t, a[AttrURL])
	}
}

func TestS3_prefilterSkipsBucket(t *testing.T) {
	// httptest server that fails the test if it is ever hit; the prefilter must
	// short-circuit before any S3 request is made.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request %s %s", r.Method, r.URL)
	}))
	defer srv.Close()
	s := &S3{
		URL:       fmt.Sprintf("%s/mybucket/", srv.URL),
		Region:    "us-east-1",
		AccessKey: "ak", SecretKey: "sk",
		ShouldSkip: func(attrs map[string]string) bool {
			return attrs[AttrS3Bucket] == "mybucket"
		},
	}
	require.NoError(t, s.Validate())
	require.NoError(t, s.Fragments(context.Background(), func(Fragment, error) error {
		t.Fatal("yield called for skipped bucket")
		return nil
	}))
}

func TestS3_skipsBeforeFetch(t *testing.T) {
	listResp := s3ListBucketResult{
		Name: "mybucket",
		Contents: []s3Object{
			{Key: "glacier.txt", Size: 100, StorageClass: s3StorageClassGlacier},
			{Key: "huge.bin", Size: 10_000_000_000, StorageClass: "STANDARD"},
			{Key: "empty.txt", Size: 0, StorageClass: "STANDARD"},
			{Key: "dir/", Size: 0, StorageClass: "STANDARD"},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("list-type") == "2" {
			require.NoError(t, xml.NewEncoder(w).Encode(listResp))
			return
		}
		t.Fatalf("unexpected GET for %s", r.URL)
	}))
	defer srv.Close()
	s := &S3{
		URL:       fmt.Sprintf("%s/mybucket/", srv.URL),
		Region:    "us-east-1",
		AccessKey: "ak", SecretKey: "sk",
	}
	require.NoError(t, s.Validate())
	require.NoError(t, s.Fragments(context.Background(), func(Fragment, error) error {
		t.Fatal("no objects should be yielded")
		return nil
	}))
}
