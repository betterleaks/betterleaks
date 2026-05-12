package sources

import (
	"context"
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
		{
			name: "aws dualstack virtual-hosted",
			raw:  "https://my-bucket.s3.dualstack.us-west-2.amazonaws.com/foo",
			want: s3Target{
				Scheme: "https", Host: "my-bucket.s3.dualstack.us-west-2.amazonaws.com",
				Bucket: "my-bucket", Prefix: "foo",
				Region: "us-west-2", IsAWS: true,
				Endpoint: "my-bucket.s3.dualstack.us-west-2.amazonaws.com",
			},
		},
		{
			name: "aws dualstack path-style",
			raw:  "https://s3.dualstack.us-east-1.amazonaws.com/mybucket/x",
			want: s3Target{
				Scheme: "https", Host: "s3.dualstack.us-east-1.amazonaws.com",
				Bucket: "mybucket", Prefix: "x",
				Region: "us-east-1", PathStyle: true, IsAWS: true,
				Endpoint: "s3.dualstack.us-east-1.amazonaws.com",
			},
		},
		{name: "empty s3 host", raw: "s3:///foo", expectErr: true},
		{name: "path-style no bucket", raw: "https://s3.us-west-2.amazonaws.com/", expectErr: true},
		{name: "generic no bucket", raw: "https://example.com/", expectErr: true},
		{name: "bad scheme", raw: "ftp://host/bucket", expectErr: true},
		{name: "accelerate rejected", raw: "https://bucket.s3-accelerate.amazonaws.com/", expectErr: true},
		{name: "fips rejected", raw: "https://bucket.s3-fips.us-east-1.amazonaws.com/", expectErr: true},
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

// TestS3Sign_passesThroughToSigv4 verifies the thin wrapper delegates to the
// shared sigv4 package and produces a /s3/ scope.
func TestS3Sign_passesThroughToSigv4(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://mybucket.s3.us-east-1.amazonaws.com/?list-type=2", nil)
	require.NoError(t, err)
	creds := s3Creds{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
	require.NoError(t, s3Sign(req, nil, "us-east-1", creds))

	auth := req.Header.Get("Authorization")
	require.Contains(t, auth, "AWS4-HMAC-SHA256 ")
	require.Contains(t, auth, "/us-east-1/s3/aws4_request")
	require.NotEmpty(t, req.Header.Get("X-Amz-Date"))
	require.NotEmpty(t, req.Header.Get("X-Amz-Content-Sha256"))
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

func TestS3ParseURL_globs(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		want      s3Target
		expectErr bool
	}{
		{
			name: "s3 scheme star",
			raw:  "s3://*",
			want: s3Target{
				Scheme: "https", Host: "s3.amazonaws.com",
				BucketGlob: "*",
				IsAWS:      true, RequiresProbe: true,
				Endpoint: "s3.amazonaws.com",
			},
		},
		{
			name: "s3 scheme glob with prefix",
			raw:  "s3://prod-*/logs/",
			want: s3Target{
				Scheme: "https", Host: "s3.amazonaws.com",
				BucketGlob: "prod-*", Prefix: "logs/",
				IsAWS: true, RequiresProbe: true,
				Endpoint: "s3.amazonaws.com",
			},
		},
		{
			name: "aws path-style glob",
			raw:  "https://s3.us-west-2.amazonaws.com/*/foo",
			want: s3Target{
				Scheme: "https", Host: "s3.us-west-2.amazonaws.com",
				BucketGlob: "*", Prefix: "foo",
				Region: "us-west-2", PathStyle: true, IsAWS: true,
				Endpoint: "s3.us-west-2.amazonaws.com",
			},
		},
		{
			name: "minio path-style glob",
			raw:  "http://localhost:9000/prod-*/logs/",
			want: s3Target{
				Scheme: "http", Host: "localhost:9000",
				BucketGlob: "prod-*", Prefix: "logs/",
				PathStyle: true, Endpoint: "localhost:9000",
			},
		},
		{
			name: "r2 path-style glob",
			raw:  "https://acct.r2.cloudflarestorage.com/*",
			want: s3Target{
				Scheme: "https", Host: "acct.r2.cloudflarestorage.com",
				BucketGlob: "*", Region: "auto",
				PathStyle: true, Endpoint: "acct.r2.cloudflarestorage.com",
			},
		},
		{name: "glob in dns hostname rejected", raw: "https://*.s3.amazonaws.com/", expectErr: true},
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
			assert.True(t, got.IsEnumerate(), "expected enumerate mode")
		})
	}
}

// TestS3_enumerateMatchesGlob points the source at an httptest server that
// serves a ListBuckets response followed by per-bucket ListObjectsV2 + GetObject.
// Only the two buckets matching "prod-*" should be scanned.
func TestS3_enumerateMatchesGlob(t *testing.T) {
	const (
		bucketProdA = "prod-a"
		bucketProdB = "prod-b"
		bucketDev   = "dev-one"
	)
	objects := map[string]map[string]string{
		bucketProdA: {"x.txt": "x-content"},
		bucketProdB: {"y.txt": "y-content"},
	}

	listAll := s3ListAllMyBucketsResult{
		Buckets: []s3BucketEntry{
			{Name: bucketProdA, CreationDate: "2024-01-01T00:00:00Z"},
			{Name: bucketProdB, CreationDate: "2024-01-02T00:00:00Z"},
			{Name: bucketDev, CreationDate: "2024-01-03T00:00:00Z"},
		},
	}

	var listBucketsHits int
	var devHits int
	var hitMu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NotEmpty(t, r.Header.Get("Authorization"))

		// Account-level ListBuckets: GET / (no path-style bucket prefix).
		if r.URL.Path == "/" && r.URL.RawQuery == "" {
			hitMu.Lock()
			listBucketsHits++
			hitMu.Unlock()
			require.NoError(t, xml.NewEncoder(w).Encode(listAll))
			return
		}

		// Path-style: /<bucket>/...
		segments := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
		bucket := segments[0]
		hitMu.Lock()
		if bucket == bucketDev {
			devHits++
		}
		hitMu.Unlock()

		if r.URL.Query().Get("list-type") == "2" {
			objs := objects[bucket]
			result := s3ListBucketResult{Name: bucket}
			for k, v := range objs {
				result.Contents = append(result.Contents, s3Object{
					Key: k, Size: int64(len(v)), StorageClass: "STANDARD",
					LastModified: "2024-01-01T00:00:00Z", ETag: `"e"`,
				})
			}
			require.NoError(t, xml.NewEncoder(w).Encode(result))
			return
		}
		// GetObject
		var key string
		if len(segments) == 2 {
			key = segments[1]
		}
		body, ok := objects[bucket][key]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	s := &S3{
		URL:       fmt.Sprintf("%s/prod-*", srv.URL),
		Region:    "us-east-1",
		AccessKey: "ak", SecretKey: "sk",
	}
	require.NoError(t, s.Validate())
	require.True(t, s.parsed.IsEnumerate())
	require.Equal(t, "prod-*", s.parsed.BucketGlob)

	var seenKeys []string
	var mu sync.Mutex
	require.NoError(t, s.Fragments(context.Background(), func(f Fragment, err error) error {
		require.NoError(t, err)
		mu.Lock()
		defer mu.Unlock()
		seenKeys = append(seenKeys, f.Attr(AttrS3Bucket)+":"+f.Attr(AttrS3Key))
		return nil
	}))

	assert.Equal(t, 1, listBucketsHits)
	assert.Zero(t, devHits, "dev-one bucket should not have been scanned")
	assert.ElementsMatch(t, []string{"prod-a:x.txt", "prod-b:y.txt"}, seenKeys)
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
