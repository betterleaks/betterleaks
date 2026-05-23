package sources

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/betterleaks/betterleaks/internal/sigv4"
	"github.com/betterleaks/betterleaks/logging"
)

const (
	s3DefaultMaxObjectSize int64 = 250 * 1024 * 1024 // 250 MiB
	s3DefaultWorkers             = 16
	// s3PerObjectTimeout covers the full per-object scan (HTTP GET + body
	// read + content scanning). Sized for the default 250 MiB cap at modest
	// bandwidth, with room for archive extraction.
	s3PerObjectTimeout        = 5 * time.Minute
	s3ListPageSize            = 1000
	s3Service                 = "s3"
	s3StorageClassGlacier     = "GLACIER"
	s3StorageClassGlacierIR   = "GLACIER_IR"
	s3StorageClassDeepArchive = "DEEP_ARCHIVE"
)

// S3 enumerates objects in an S3 (or S3-compatible) bucket and yields a
// fragment for each object's content. The target is described by a single URL
// passed via S3.URL.
type S3 struct {
	// URL is the target bucket (and optional prefix). Required. Supported forms:
	//
	//   s3://bucket/prefix
	//   https://bucket.s3.amazonaws.com/prefix
	//   https://bucket.s3.<region>.amazonaws.com/prefix
	//   https://s3.<region>.amazonaws.com/bucket/prefix
	//   https://<bucket>.<account>.r2.cloudflarestorage.com/prefix
	//   https://<endpoint>[:port]/bucket/prefix      (MinIO, generic S3-compat)
	URL string

	// Region overrides whatever the URL implies. Required when the URL is a
	// path-style endpoint with no inferable region (e.g. MinIO at a custom host).
	Region string

	// Credentials. Explicit fields win over environment variables. If both are
	// empty and Anonymous is false, the source fails Validate.
	AccessKey    string
	SecretKey    string
	SessionToken string
	Anonymous    bool

	// Scan config
	MaxObjectSize   int64
	Workers         int
	ShouldSkip      SkipFunc
	MaxArchiveDepth int

	parsed s3Target
	creds  s3Creds
}

// s3Target captures everything the request builder needs after URL parsing.
type s3Target struct {
	Scheme        string // "https" or "http"
	Host          string // request host. For virtual-hosted single-bucket, includes the bucket subdomain. In enumerate mode, this is the endpoint without any bucket prefix.
	Bucket        string // exact bucket name (single-bucket mode)
	BucketGlob    string // glob pattern in enumerate mode (e.g. "*", "prod-*")
	Prefix        string
	Region        string // may be "" pre-probe for AWS forms missing region
	PathStyle     bool
	IsAWS         bool // true for *.amazonaws.com and s3:// scheme
	RequiresProbe bool // AWS hosts where region was not in the URL
	Endpoint      string
}

// IsEnumerate reports whether the target is a bucket-enumeration target rather
// than a single-bucket target.
func (t s3Target) IsEnumerate() bool { return t.BucketGlob != "" }

// s3Creds holds resolved request-signing credentials.
type s3Creds struct {
	AccessKey    string
	SecretKey    string
	SessionToken string
	Anonymous    bool
}

// Validate parses the URL, resolves credentials, and (for AWS single-bucket
// targets without an explicit region) probes the bucket region. In enumerate
// mode, region resolution is deferred to scan time on a per-bucket basis.
func (s *S3) Validate() error {
	if s.URL == "" {
		return errors.New("target URL is required")
	}
	target, err := s3ParseURL(s.URL)
	if err != nil {
		return fmt.Errorf("invalid S3 URL: %w", err)
	}
	if s.Region != "" {
		target.Region = s.Region
		target.RequiresProbe = false
	}
	switch {
	case target.IsEnumerate() && target.IsAWS && target.Region == "":
		// ListBuckets is account-scoped; us-east-1 is the conventional default
		// for SigV4 scope. Per-bucket region is resolved later.
		target.Region = "us-east-1"
		target.RequiresProbe = false
	case target.RequiresProbe && target.IsAWS && target.Region == "":
		region, err := s3ProbeAWSRegion(context.Background(), target.Bucket)
		if err != nil {
			return fmt.Errorf("could not determine bucket region (pass --region): %w", err)
		}
		target.Region = region
		if !target.PathStyle {
			target.Host = fmt.Sprintf("%s.s3.%s.amazonaws.com", target.Bucket, region)
		}
		target.RequiresProbe = false
	}
	if target.Region == "" {
		return errors.New("region could not be inferred from URL; pass --region")
	}
	s.parsed = target

	creds, err := s.resolveCreds()
	if err != nil {
		return err
	}
	s.creds = creds
	return nil
}

// resolveCreds applies the auth waterfall:
//
//	Anonymous flag         → anonymous
//	Explicit fields        → static
//	AWS_* env vars         → static
//	None of the above      → error (fail loud)
func (s *S3) resolveCreds() (s3Creds, error) {
	if s.Anonymous {
		return s3Creds{Anonymous: true}, nil
	}
	if s.AccessKey != "" && s.SecretKey != "" {
		return s3Creds{
			AccessKey:    s.AccessKey,
			SecretKey:    s.SecretKey,
			SessionToken: s.SessionToken,
		}, nil
	}
	envAK := os.Getenv("AWS_ACCESS_KEY_ID")
	envSK := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if envAK != "" && envSK != "" {
		return s3Creds{
			AccessKey:    envAK,
			SecretKey:    envSK,
			SessionToken: os.Getenv("AWS_SESSION_TOKEN"),
		}, nil
	}
	return s3Creds{}, errors.New("no credentials: set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, pass --access-key/--secret-key, or pass --anonymous")
}

// Fragments dispatches to single-bucket or enumerate-mode scanning based on
// the parsed URL.
func (s *S3) Fragments(ctx context.Context, yield FragmentsFunc) error {
	if s.parsed.Bucket == "" && s.parsed.BucketGlob == "" {
		if err := s.Validate(); err != nil {
			return err
		}
	}
	httpClient := &http.Client{}
	if s.parsed.IsEnumerate() {
		return s.scanEnumerated(ctx, httpClient, yield)
	}
	return s.scanBucket(ctx, httpClient, s.parsed, yield)
}

// scanEnumerated lists buckets at the endpoint, filters by glob, and scans
// each matched bucket. Per-bucket failures (e.g. AccessDenied, region probe
// errors) are logged and non-fatal.
func (s *S3) scanEnumerated(ctx context.Context, client *http.Client, yield FragmentsFunc) error {
	logging.Info().
		Str("endpoint", s.parsed.Endpoint).
		Str("bucket_glob", s.parsed.BucketGlob).
		Str("region", s.parsed.Region).
		Msg("enumerating buckets")

	buckets, err := s3ListAllBuckets(ctx, client, s.parsed, s.creds)
	if err != nil {
		return fmt.Errorf("list buckets: %w", err)
	}

	var matched []string
	for _, b := range buckets {
		ok, err := path.Match(s.parsed.BucketGlob, b)
		if err != nil {
			return fmt.Errorf("invalid bucket glob %q: %w", s.parsed.BucketGlob, err)
		}
		if ok {
			matched = append(matched, b)
		}
	}
	logging.Info().Int("total", len(buckets)).Int("matched", len(matched)).Msg("bucket enumeration complete")

	for _, b := range matched {
		sub, err := s.bucketSubTarget(ctx, b)
		if err != nil {
			logging.Error().Err(err).Str("bucket", b).Msg("could not resolve bucket; skipping")
			continue
		}
		if err := s.scanBucket(ctx, client, sub, yield); err != nil {
			logging.Error().Err(err).Str("bucket", b).Msg("bucket scan failed; continuing")
		}
	}
	return nil
}

// bucketSubTarget builds a single-bucket target derived from the enumerate
// target. For AWS, this probes the bucket's region (which may differ from the
// account's default).
func (s *S3) bucketSubTarget(ctx context.Context, bucket string) (s3Target, error) {
	sub := s.parsed
	sub.Bucket = bucket
	sub.BucketGlob = ""

	if sub.IsAWS {
		region, err := s3ProbeAWSRegion(ctx, bucket)
		if err != nil {
			return s3Target{}, fmt.Errorf("probe region: %w", err)
		}
		sub.Region = region
		if sub.PathStyle {
			sub.Host = fmt.Sprintf("s3.%s.amazonaws.com", region)
		} else {
			sub.Host = fmt.Sprintf("%s.s3.%s.amazonaws.com", bucket, region)
		}
	}
	return sub, nil
}

// scanBucket runs the list-then-fetch loop for a single bucket described by
// target.
func (s *S3) scanBucket(ctx context.Context, client *http.Client, target s3Target, yield FragmentsFunc) error {
	maxSize := s.MaxObjectSize
	if maxSize <= 0 {
		maxSize = s3DefaultMaxObjectSize
	}
	workers := s.Workers
	if workers <= 0 {
		workers = s3DefaultWorkers
	}

	bucketAttrs := map[string]string{
		AttrS3Bucket: target.Bucket,
		AttrS3Region: target.Region,
		AttrResource: ResourceS3Object,
	}
	if target.Endpoint != "" {
		bucketAttrs[AttrS3Endpoint] = target.Endpoint
	}
	if s.ShouldSkip != nil && s.ShouldSkip(bucketAttrs) {
		logging.Info().Str("bucket", target.Bucket).Msg("skipping bucket: filtered by prefilter")
		return nil
	}

	logging.Info().
		Str("bucket", target.Bucket).
		Str("region", target.Region).
		Str("prefix", target.Prefix).
		Str("endpoint", target.Endpoint).
		Msg("starting S3 scan")

	start := time.Now()
	var (
		listedCount  int // every object returned by ListObjectsV2
		scannedCount int // objects fully fetched + processed without error
		mu           sync.Mutex
	)

	var continuationToken string
	for {
		page, err := s3ListPage(ctx, client, target, s.creds, target.Prefix, continuationToken)
		if err != nil {
			return fmt.Errorf("list objects: %w", err)
		}
		listedCount += len(page.Contents)

		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(workers)
		for _, obj := range page.Contents {
			if skipReason := s.skipReason(obj, maxSize); skipReason != "" {
				logging.Trace().Str("key", obj.Key).Str("reason", skipReason).Msg("skipping object")
				continue
			}
			attrs := s.objectAttributes(target, obj)
			if s.ShouldSkip != nil && s.ShouldSkip(attrs) {
				logging.Trace().Str("key", obj.Key).Msg("skipping object: filtered by prefilter")
				continue
			}
			g.Go(func() error {
				if err := s.scanObject(gctx, client, target, obj, attrs, yield); err != nil {
					logging.Error().Err(err).Str("key", obj.Key).Msg("could not scan S3 object")
					return nil
				}
				mu.Lock()
				scannedCount++
				mu.Unlock()
				return nil
			})
		}
		if err := g.Wait(); err != nil {
			return err
		}
		if !page.IsTruncated || page.NextContinuationToken == "" {
			break
		}
		continuationToken = page.NextContinuationToken
	}

	logging.Info().
		Str("bucket", target.Bucket).
		Int("objects_listed", listedCount).
		Int("objects_scanned", scannedCount).
		Str("duration", time.Since(start).Round(time.Millisecond).String()).
		Msg("S3 scan complete")
	return nil
}

// skipReason returns a non-empty reason if the object should be skipped before
// attempting to fetch it. The empty string means "scan it".
func (s *S3) skipReason(obj s3Object, maxSize int64) string {
	switch obj.StorageClass {
	case s3StorageClassGlacier, s3StorageClassGlacierIR, s3StorageClassDeepArchive:
		return "storage_class:" + obj.StorageClass
	}
	if obj.Size > maxSize {
		return "size_limit"
	}
	if obj.Size == 0 {
		return "empty"
	}
	if strings.HasSuffix(obj.Key, "/") {
		return "directory"
	}
	return ""
}

// objectAttributes builds the attr map stamped on every fragment for this object.
func (s *S3) objectAttributes(target s3Target, obj s3Object) map[string]string {
	attrs := map[string]string{
		AttrPath:           obj.Key,
		AttrURL:            s3ObjectURL(target, obj.Key),
		AttrResource:       ResourceS3Object,
		AttrS3Bucket:       target.Bucket,
		AttrS3Key:          obj.Key,
		AttrS3Region:       target.Region,
		AttrS3Size:         strconv.FormatInt(obj.Size, 10),
		AttrS3ETag:         strings.Trim(obj.ETag, `"`),
		AttrS3LastModified: obj.LastModified,
		AttrS3StorageClass: obj.StorageClass,
	}
	if target.Endpoint != "" {
		attrs[AttrS3Endpoint] = target.Endpoint
	}
	return attrs
}

// scanObject GETs an object and pipes its body through File.Fragments, which
// already handles archives, mime sniffing, and chunk boundaries.
func (s *S3) scanObject(ctx context.Context, client *http.Client, target s3Target, obj s3Object, attrs map[string]string, yield FragmentsFunc) error {
	objCtx, cancel := context.WithTimeout(ctx, s3PerObjectTimeout)
	defer cancel()

	body, err := s3GetObject(objCtx, client, target, s.creds, obj.Key)
	if err != nil {
		return err
	}
	defer body.Close()

	stampedYield := s.wrapYieldWithAttrs(attrs, yield)
	file := &File{
		Content:         body,
		Path:            obj.Key,
		MaxArchiveDepth: s.MaxArchiveDepth,
		ShouldSkip:      s.ShouldSkip,
	}
	return file.Fragments(objCtx, stampedYield)
}

// wrapYieldWithAttrs returns a yield that stamps the given attrs on every
// fragment, re-applies ShouldSkip with the merged attrs, and serializes calls
// through a mutex. Mirrors the GitHub source.
func (s *S3) wrapYieldWithAttrs(attrs map[string]string, yield FragmentsFunc) FragmentsFunc {
	var mu sync.Mutex
	return func(fragment Fragment, err error) error {
		if err == nil {
			for k, v := range attrs {
				if v == "" {
					continue
				}
				// Always override AttrResource so the fragment reflects the S3
				// source rather than the File source's default "fs.content".
				if k == AttrResource || fragment.Attr(k) == "" {
					fragment.SetAttr(k, v)
				}
			}
			if s.ShouldSkip != nil && s.ShouldSkip(fragment.Attributes) {
				return nil
			}
		}
		mu.Lock()
		defer mu.Unlock()
		return yield(fragment, err)
	}
}

// s3ParseURL accepts the documented URL forms and returns a populated s3Target.
// Globs are allowed in the bucket position only ("s3://<here>" or the first
// path segment of path-style URLs). Globs in DNS hostnames (virtual-hosted AWS
// or R2 forms) are rejected so users go through the explicit s3:// or
// path-style forms for enumeration.
func s3ParseURL(raw string) (s3Target, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return s3Target{}, err
	}
	switch u.Scheme {
	case "s3":
		if u.Host == "" {
			return s3Target{}, errors.New("s3:// URL is missing bucket")
		}
		t := s3Target{
			Scheme:        "https",
			Prefix:        strings.TrimPrefix(u.Path, "/"),
			IsAWS:         true,
			RequiresProbe: true,
			Endpoint:      "s3.amazonaws.com",
		}
		if s3IsGlob(u.Host) {
			t.BucketGlob = u.Host
			t.Host = "s3.amazonaws.com"
		} else {
			t.Bucket = u.Host
			t.Host = fmt.Sprintf("%s.s3.amazonaws.com", u.Host)
		}
		return t, nil
	case "http", "https":
		// fall through
	default:
		return s3Target{}, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}

	host := u.Host
	hostOnly := host
	if i := strings.IndexByte(hostOnly, ':'); i >= 0 {
		hostOnly = hostOnly[:i]
	}
	if s3IsGlob(hostOnly) {
		return s3Target{}, errors.New("glob is not allowed in the hostname; use s3://<glob> or path-style https://endpoint/<glob>")
	}
	path := strings.TrimPrefix(u.Path, "/")

	switch {
	case strings.HasSuffix(hostOnly, ".amazonaws.com") || hostOnly == "amazonaws.com":
		return parseAWSHostURL(u, hostOnly, path)
	case strings.HasSuffix(hostOnly, ".r2.cloudflarestorage.com"):
		return parseR2HostURL(u, hostOnly, path)
	default:
		// Generic S3-compatible: assume path-style; first path segment is bucket.
		bucket, prefix := splitBucketAndPrefix(path)
		if bucket == "" {
			return s3Target{}, errors.New("path-style URL is missing bucket segment")
		}
		t := s3Target{
			Scheme:    u.Scheme,
			Host:      host,
			Prefix:    prefix,
			PathStyle: true,
			Endpoint:  host,
		}
		if s3IsGlob(bucket) {
			t.BucketGlob = bucket
		} else {
			t.Bucket = bucket
		}
		return t, nil
	}
}

// s3IsGlob reports whether s contains glob metacharacters. Real S3 bucket names
// cannot contain '*', '?', or '[', so any of these unambiguously signals
// enumeration mode.
func s3IsGlob(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// parseAWSHostURL handles the AWS-hosted forms:
//
//	<bucket>.s3.amazonaws.com              (region probe required)
//	<bucket>.s3.<region>.amazonaws.com
//	s3.amazonaws.com / <bucket>            (legacy path-style, probe required)
//	s3.<region>.amazonaws.com / <bucket>
func parseAWSHostURL(u *url.URL, hostOnly, path string) (s3Target, error) {
	labels := strings.Split(hostOnly, ".")
	// suffix is always [..., "amazonaws", "com"]; strip it.
	if len(labels) < 3 {
		return s3Target{}, fmt.Errorf("unrecognized amazonaws.com host %q", hostOnly)
	}
	prefix := labels[:len(labels)-2]

	// Reject accelerate / fips variants explicitly so users get a clear error
	// rather than a hard-to-debug auth failure. The regional virtual-hosted
	// form works for the same buckets.
	for _, label := range prefix {
		switch {
		case label == "s3-accelerate", label == "s3-accelerate-fips":
			return s3Target{}, fmt.Errorf("S3 Transfer Acceleration endpoint %q is not supported; use the regional form like bucket.s3.<region>.amazonaws.com", hostOnly)
		case strings.HasPrefix(label, "s3-fips"):
			return s3Target{}, fmt.Errorf("S3 FIPS endpoint %q is not supported; use the regional form like bucket.s3.<region>.amazonaws.com", hostOnly)
		}
	}

	// Virtual-hosted: bucket.s3[.dualstack][.region].amazonaws.com
	for i := 1; i < len(prefix); i++ {
		if prefix[i] == "s3" {
			bucket := strings.Join(prefix[:i], ".")
			rest := prefix[i+1:]
			// "dualstack" is an IPv6-capable qualifier that appears between
			// "s3" and the region. Skip it; signing region is the one after.
			if len(rest) >= 1 && rest[0] == "dualstack" {
				rest = rest[1:]
			}
			region := ""
			if len(rest) >= 1 {
				region = rest[0]
			}
			bPrefix := path
			return s3Target{
				Scheme:        u.Scheme,
				Host:          u.Host,
				Bucket:        bucket,
				Prefix:        bPrefix,
				Region:        region,
				IsAWS:         true,
				RequiresProbe: region == "",
				Endpoint:      hostOnly,
			}, nil
		}
	}

	// Path-style: s3[.dualstack][.region].amazonaws.com / bucket
	if prefix[0] == "s3" {
		rest := prefix[1:]
		if len(rest) >= 1 && rest[0] == "dualstack" {
			rest = rest[1:]
		}
		region := ""
		if len(rest) >= 1 {
			region = rest[0]
		}
		bucket, bPrefix := splitBucketAndPrefix(path)
		if bucket == "" {
			return s3Target{}, errors.New("path-style amazonaws.com URL is missing bucket segment")
		}
		t := s3Target{
			Scheme:        u.Scheme,
			Host:          u.Host,
			Prefix:        bPrefix,
			Region:        region,
			PathStyle:     true,
			IsAWS:         true,
			RequiresProbe: region == "",
			Endpoint:      hostOnly,
		}
		if s3IsGlob(bucket) {
			t.BucketGlob = bucket
		} else {
			t.Bucket = bucket
		}
		return t, nil
	}

	return s3Target{}, fmt.Errorf("unrecognized amazonaws.com host %q", hostOnly)
}

// parseR2HostURL handles Cloudflare R2's `*.r2.cloudflarestorage.com` host.
// R2 ignores region but SigV4 requires one; the canonical value is "auto".
func parseR2HostURL(u *url.URL, hostOnly, path string) (s3Target, error) {
	labels := strings.Split(hostOnly, ".")
	// Expect at least <account>.r2.cloudflarestorage.com, optionally with a
	// leading <bucket> label for virtual-hosted form.
	if len(labels) < 4 {
		return s3Target{}, fmt.Errorf("unrecognized r2 host %q", hostOnly)
	}
	// Virtual-hosted: <bucket>.<account>.r2.cloudflarestorage.com
	if len(labels) >= 5 {
		bucket := labels[0]
		return s3Target{
			Scheme:   u.Scheme,
			Host:     u.Host,
			Bucket:   bucket,
			Prefix:   path,
			Region:   "auto",
			IsAWS:    false,
			Endpoint: hostOnly,
		}, nil
	}
	// Path-style: <account>.r2.cloudflarestorage.com/<bucket>/<prefix>
	bucket, bPrefix := splitBucketAndPrefix(path)
	if bucket == "" {
		return s3Target{}, errors.New("r2 URL is missing bucket segment")
	}
	t := s3Target{
		Scheme:    u.Scheme,
		Host:      u.Host,
		Prefix:    bPrefix,
		Region:    "auto",
		PathStyle: true,
		IsAWS:     false,
		Endpoint:  hostOnly,
	}
	if s3IsGlob(bucket) {
		t.BucketGlob = bucket
	} else {
		t.Bucket = bucket
	}
	return t, nil
}

// splitBucketAndPrefix splits a path of the form "bucket/prefix..." into its parts.
// Both pieces are returned without leading or trailing slashes (prefix keeps internal "/").
func splitBucketAndPrefix(path string) (bucket, prefix string) {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return "", ""
	}
	b, p, _ := strings.Cut(path, "/")
	return b, p
}

// ---------------------------------------------------------------------------
// Region probe (AWS only)
// ---------------------------------------------------------------------------

// s3ProbeAWSRegion issues a HEAD against the bucket's global endpoint and reads
// the x-amz-bucket-region header. AWS sets this header on success and on the
// `301 PermanentRedirect` it returns when the bucket lives elsewhere.
func s3ProbeAWSRegion(ctx context.Context, bucket string) (string, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodHead, fmt.Sprintf("https://%s.s3.amazonaws.com", bucket), nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{
		// Don't follow the 301 redirect; we just want the header.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	region := resp.Header.Get("x-amz-bucket-region")
	if region == "" {
		return "", fmt.Errorf("HEAD %s returned %s with no x-amz-bucket-region header", req.URL, resp.Status)
	}
	return region, nil
}

// s3BucketEntry mirrors the <Bucket> element inside a ListAllMyBucketsResult.
type s3BucketEntry struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

type s3ListAllMyBucketsResult struct {
	XMLName xml.Name        `xml:"ListAllMyBucketsResult"`
	Buckets []s3BucketEntry `xml:"Buckets>Bucket"`
}

// s3ListAllBuckets issues GET / against the endpoint host (no bucket subdomain
// or path segment) and returns the bucket names. Requires the
// s3:ListAllMyBuckets permission on AWS; non-AWS providers have equivalent
// account-level credentials.
func s3ListAllBuckets(ctx context.Context, client *http.Client, target s3Target, creds s3Creds) ([]string, error) {
	// Build a target that addresses the endpoint root: same host as the
	// enumerate target, no bucket path segment.
	endpointTarget := target
	endpointTarget.Bucket = ""
	endpointTarget.BucketGlob = ""
	endpointTarget.PathStyle = false // request path stays "/" with no bucket prefix

	req, err := s3NewRequest(ctx, http.MethodGet, endpointTarget, "", nil)
	if err != nil {
		return nil, err
	}
	if err := s3Sign(req, nil, target.Region, creds); err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("list-buckets returned %s: %s", resp.Status, strings.TrimSpace(string(snippet)))
	}
	var result s3ListAllMyBucketsResult
	if err := xml.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode list-buckets response: %w", err)
	}
	names := make([]string, 0, len(result.Buckets))
	for _, b := range result.Buckets {
		names = append(names, b.Name)
	}
	return names, nil
}

type s3Object struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

type s3ListBucketResult struct {
	XMLName               xml.Name   `xml:"ListBucketResult"`
	Name                  string     `xml:"Name"`
	Prefix                string     `xml:"Prefix"`
	KeyCount              int        `xml:"KeyCount"`
	MaxKeys               int        `xml:"MaxKeys"`
	IsTruncated           bool       `xml:"IsTruncated"`
	NextContinuationToken string     `xml:"NextContinuationToken"`
	Contents              []s3Object `xml:"Contents"`
}

// s3ListPage requests one page of ListObjectsV2.
func s3ListPage(ctx context.Context, client *http.Client, target s3Target, creds s3Creds, prefix, continuationToken string) (*s3ListBucketResult, error) {
	query := url.Values{}
	query.Set("list-type", "2")
	query.Set("max-keys", strconv.Itoa(s3ListPageSize))
	if prefix != "" {
		query.Set("prefix", prefix)
	}
	if continuationToken != "" {
		query.Set("continuation-token", continuationToken)
	}

	req, err := s3NewRequest(ctx, http.MethodGet, target, "", query)
	if err != nil {
		return nil, err
	}
	if err := s3Sign(req, nil, target.Region, creds); err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("list returned %s: %s", resp.Status, strings.TrimSpace(string(snippet)))
	}
	var result s3ListBucketResult
	if err := xml.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode list response: %w", err)
	}
	return &result, nil
}

// s3GetObject signs and issues GET /<key>. The caller closes the returned body.
func s3GetObject(ctx context.Context, client *http.Client, target s3Target, creds s3Creds, key string) (io.ReadCloser, error) {
	req, err := s3NewRequest(ctx, http.MethodGet, target, key, nil)
	if err != nil {
		return nil, err
	}
	if err := s3Sign(req, nil, target.Region, creds); err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		return nil, fmt.Errorf("get returned %s: %s", resp.Status, strings.TrimSpace(string(snippet)))
	}
	return resp.Body, nil
}

// s3NewRequest builds an http.Request targeting the given key, taking
// virtual-hosted vs path-style into account.
func s3NewRequest(ctx context.Context, method string, target s3Target, key string, query url.Values) (*http.Request, error) {
	path := "/"
	if target.PathStyle {
		path = "/" + target.Bucket
	}
	if key != "" {
		// Each key segment URI-encoded; "/" preserved between segments.
		path = strings.TrimSuffix(path, "/") + "/" + s3EncodeKey(key)
	}
	// Build the URL string directly so the percent-encoded path we computed is
	// what hits the wire. Going through url.URL{Path: path}.String() would
	// re-escape '%' into '%25' (double-encoding), invalidating the signature
	// and routing for any key containing a non-unreserved character.
	urlStr := target.Scheme + "://" + target.Host + path
	if len(query) > 0 {
		urlStr += "?" + query.Encode()
	}
	return http.NewRequestWithContext(ctx, method, urlStr, nil)
}

// s3ObjectURL builds a virtual-hosted-style public URL for the given key.
// Used as AttrURL on findings.
func s3ObjectURL(target s3Target, key string) string {
	path := s3EncodeKey(key)
	if target.PathStyle {
		return fmt.Sprintf("%s://%s/%s/%s", target.Scheme, target.Host, target.Bucket, path)
	}
	return fmt.Sprintf("%s://%s/%s", target.Scheme, target.Host, path)
}

// s3Sign signs req using SigV4 (s3 service) unless creds are anonymous, in
// which case it leaves the request unsigned for buckets with public read.
func s3Sign(req *http.Request, body []byte, region string, creds s3Creds) error {
	if creds.Anonymous {
		return nil
	}
	return sigv4.Sign(req, body, region, s3Service, sigv4.Credentials{
		AccessKey:    creds.AccessKey,
		SecretKey:    creds.SecretKey,
		SessionToken: creds.SessionToken,
	})
}

// s3EncodeKey URI-encodes a key, preserving "/" between segments. Used when
// constructing request URLs.
func s3EncodeKey(key string) string {
	return sigv4.URIEncode(key, false)
}
