package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/internal/httpclient"
)

func TestParseHuggingFaceURL(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    *ParsedHuggingFaceURL
		wantErr bool
	}{
		{
			name: "owner",
			raw:  "https://huggingface.co/acme",
			want: &ParsedHuggingFaceURL{Scheme: "https", Host: "huggingface.co", Kind: "owner", Owner: "acme"},
		},
		{
			name: "model",
			raw:  "https://huggingface.co/acme/model",
			want: &ParsedHuggingFaceURL{Scheme: "https", Host: "huggingface.co", Kind: "repo", Owner: "acme", Name: "model", Type: HuggingFaceRepoKindModel},
		},
		{
			name: "dataset",
			raw:  "https://huggingface.co/datasets/acme/data.git",
			want: &ParsedHuggingFaceURL{Scheme: "https", Host: "huggingface.co", Kind: "repo", Owner: "acme", Name: "data", Type: HuggingFaceRepoKindDataset},
		},
		{
			name: "space",
			raw:  "https://huggingface.co/spaces/acme/demo",
			want: &ParsedHuggingFaceURL{Scheme: "https", Host: "huggingface.co", Kind: "repo", Owner: "acme", Name: "demo", Type: HuggingFaceRepoKindSpace},
		},
		{
			name: "bucket web",
			raw:  "https://huggingface.co/buckets/acme/logs/prod",
			want: &ParsedHuggingFaceURL{Scheme: "https", Host: "huggingface.co", Kind: "bucket", Owner: "acme", Name: "logs", Prefix: "prod"},
		},
		{
			name: "bucket hf",
			raw:  "hf://buckets/acme/logs/prod",
			want: &ParsedHuggingFaceURL{Scheme: "hf", Host: "buckets", Kind: "bucket", Owner: "acme", Name: "logs", Prefix: "prod"},
		},
		{name: "bad scheme", raw: "ftp://huggingface.co/acme/model", wantErr: true},
		{name: "root", raw: "https://huggingface.co/", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseHuggingFaceURL(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if *got != *tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestHuggingFaceValidate_DefaultsToRepos(t *testing.T) {
	src := &HuggingFace{URL: "https://huggingface.co/acme/model"}
	if err := src.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !src.Resources.Has(HuggingFaceResourceTypeRepos) {
		t.Fatalf("expected repos to be enabled by default")
	}
	if src.Resources.Has(HuggingFaceResourceTypeDiscussions) || src.Resources.Has(HuggingFaceResourceTypePRs) {
		t.Fatalf("community resources should be opt-in, got %v", src.Resources)
	}
}

func TestHuggingFaceValidate_BucketTargetDefaultsToBuckets(t *testing.T) {
	src := &HuggingFace{URL: "hf://buckets/acme/logs"}
	if err := src.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !src.Resources.Has(HuggingFaceResourceTypeBuckets) {
		t.Fatalf("expected buckets to be enabled for bucket target")
	}
	if src.Resources.Has(HuggingFaceResourceTypeRepos) {
		t.Fatalf("bucket target should not default to repos, got %v", src.Resources)
	}
}

func TestHuggingFaceEnumerateRepos_PaginatesAndDedupeTyped(t *testing.T) {
	var authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		switch {
		case r.URL.Path == "/api/models" && r.URL.Query().Get("cursor") == "":
			w.Header().Set("Link", "<"+serverURL(r)+"/api/models?cursor=next>; rel=\"next\"")
			_, _ = w.Write([]byte(`[{"modelId":"acme/model"}]`))
		case r.URL.Path == "/api/models":
			_, _ = w.Write([]byte(`[{"id":"acme/model"}]`))
		case r.URL.Path == "/api/datasets":
			_, _ = w.Write([]byte(`[{"id":"acme/model"}]`))
		case r.URL.Path == "/api/spaces":
			_, _ = w.Write([]byte(`[{"id":"acme/space"}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	base := mustParseURL(t, server.URL+"/")
	src := &HuggingFace{
		Token:      "secret",
		URL:        server.URL + "/acme",
		baseURL:    base,
		restRetry:  httpclient.NewRetryTransport(nil),
		httpClient: httpclient.NewAuthenticatedClient("secret", http.DefaultTransport, base.Host),
	}
	target, err := ParseHuggingFaceURL(src.URL)
	if err != nil {
		t.Fatal(err)
	}
	ch, errCh := src.enumerateRepos(context.Background(), target)
	var got []huggingFaceRepo
	for repo := range ch {
		got = append(got, repo)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("enumerateRepos: %v", err)
	}
	if authHeader != "Bearer secret" {
		t.Fatalf("Authorization = %q", authHeader)
	}
	if len(got) != 3 {
		t.Fatalf("got %d repos: %+v", len(got), got)
	}
	wantKeys := map[string]bool{"model:acme/model": true, "dataset:acme/model": true, "space:acme/space": true}
	for _, repo := range got {
		if !wantKeys[repo.CanonicalKey()] {
			t.Fatalf("unexpected repo key %q", repo.CanonicalKey())
		}
	}
}

func TestHuggingFacePaginateRejectsCrossHostNextLink(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://evil.example/api/models?cursor=next>; rel="next"`)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	src := &HuggingFace{
		baseURL:    mustParseURL(t, server.URL+"/"),
		restRetry:  httpclient.NewRetryTransport(nil),
		httpClient: http.DefaultClient,
	}
	err := src.paginateJSON(context.Background(), mustParseURL(t, server.URL+"/api/models"), func([]byte) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected cross-host pagination link to fail")
	}
	if !strings.Contains(err.Error(), "unexpected host") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHuggingFacePaginateAllowsRelativeNextLink(t *testing.T) {
	var pages int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages++
		if r.URL.Query().Get("cursor") == "" {
			w.Header().Set("Link", `</api/models?cursor=next>; rel="next"`)
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	src := &HuggingFace{
		baseURL:    mustParseURL(t, server.URL+"/"),
		restRetry:  httpclient.NewRetryTransport(nil),
		httpClient: http.DefaultClient,
	}
	err := src.paginateJSON(context.Background(), mustParseURL(t, server.URL+"/api/models"), func([]byte) error {
		return nil
	})
	if err != nil {
		t.Fatalf("paginateJSON: %v", err)
	}
	if pages != 2 {
		t.Fatalf("got %d pages, want 2", pages)
	}
}

func TestHuggingFaceScanRepoPropagatesGitError(t *testing.T) {
	src := &HuggingFace{
		Resources: HuggingFaceResourceSet{HuggingFaceResourceTypeRepos: true},
		baseURL:   mustParseURL(t, "bad://huggingface.invalid/"),
	}
	err := src.scanRepo(context.Background(), huggingFaceRepo{Kind: HuggingFaceRepoKindModel, Owner: "acme", Name: "model"}, func(Fragment, error) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected git scan error")
	}
}

func TestHuggingFaceEnumerateBuckets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/buckets/acme" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`[{"id":"acme/logs","private":true,"size":12,"total_files":2}]`))
	}))
	defer server.Close()

	src := &HuggingFace{
		URL:        server.URL + "/acme",
		baseURL:    mustParseURL(t, server.URL+"/"),
		restRetry:  httpclient.NewRetryTransport(nil),
		httpClient: http.DefaultClient,
	}
	target, err := ParseHuggingFaceURL(src.URL)
	if err != nil {
		t.Fatal(err)
	}
	ch, errCh := src.enumerateBuckets(context.Background(), target)
	var got []huggingFaceBucket
	for bucket := range ch {
		got = append(got, bucket)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("enumerateBuckets: %v", err)
	}
	if len(got) != 1 || got[0].ID() != "acme/logs" || !got[0].Private {
		t.Fatalf("unexpected buckets: %+v", got)
	}
}

func TestHuggingFaceScanBucketObject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/buckets/acme/logs/tree":
			if r.URL.Query().Get("prefix") != "prod" || r.URL.Query().Get("recursive") != "true" {
				t.Fatalf("unexpected query: %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`[{"type":"file","path":"prod/secret.txt","size":28,"lastModified":"2026-01-02T03:04:05Z","xetHash":"abc"}]`))
		case "/buckets/acme/logs/resolve/prod/secret.txt":
			_, _ = w.Write([]byte("token=AKIALALEMEL33243OLIA\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	src := &HuggingFace{
		Token:      "secret",
		URL:        "hf://buckets/acme/logs/prod",
		baseURL:    mustParseURL(t, server.URL+"/"),
		restRetry:  httpclient.NewRetryTransport(nil),
		httpClient: httpclient.NewAuthenticatedClient("secret", http.DefaultTransport, strings.TrimPrefix(server.URL, "http://")),
	}
	var fragments []Fragment
	err := src.scanBucket(context.Background(), huggingFaceBucket{Owner: "acme", Name: "logs", Prefix: "prod"}, func(fragment Fragment, err error) error {
		if err != nil {
			return err
		}
		fragments = append(fragments, fragment)
		return nil
	})
	if err != nil {
		t.Fatalf("scanBucket: %v", err)
	}
	if len(fragments) != 1 {
		t.Fatalf("got %d fragments", len(fragments))
	}
	if fragments[0].Attr(AttrResource) != ResourceHuggingFaceBucket {
		t.Fatalf("resource = %q", fragments[0].Attr(AttrResource))
	}
	if fragments[0].Attr(AttrHuggingFaceBucketPath) != "prod/secret.txt" {
		t.Fatalf("bucket path = %q", fragments[0].Attr(AttrHuggingFaceBucketPath))
	}
	if fragments[0].Attr(AttrHuggingFaceBucketSize) != "28" {
		t.Fatalf("bucket size = %q", fragments[0].Attr(AttrHuggingFaceBucketSize))
	}
	if !strings.Contains(fragments[0].Raw, "AKIALALEMEL33243OLIA") {
		t.Fatalf("raw fragment missing token: %q", fragments[0].Raw)
	}
}

func TestHuggingFaceScanBucketSkipsPrefilteredObjectBeforeDownload(t *testing.T) {
	var downloaded bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/buckets/acme/logs/tree":
			_, _ = w.Write([]byte(`[{"type":"file","path":"prod/skip.txt","size":28}]`))
		case "/buckets/acme/logs/resolve/prod/skip.txt":
			downloaded = true
			_, _ = w.Write([]byte("secret\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	src := &HuggingFace{
		URL:        "hf://buckets/acme/logs/prod",
		baseURL:    mustParseURL(t, server.URL+"/"),
		restRetry:  httpclient.NewRetryTransport(nil),
		httpClient: http.DefaultClient,
		ShouldSkip: func(attrs map[string]string) bool {
			return attrs[AttrHuggingFaceBucketPath] == "prod/skip.txt"
		},
	}
	var fragments []Fragment
	err := src.scanBucket(context.Background(), huggingFaceBucket{Owner: "acme", Name: "logs", Prefix: "prod"}, func(fragment Fragment, err error) error {
		if err != nil {
			return err
		}
		fragments = append(fragments, fragment)
		return nil
	})
	if err != nil {
		t.Fatalf("scanBucket: %v", err)
	}
	if downloaded {
		t.Fatal("prefiltered object should not be downloaded")
	}
	if len(fragments) != 0 {
		t.Fatalf("got %d fragments", len(fragments))
	}
}

func TestHuggingFaceListDiscussionsDecodesEnvelope(t *testing.T) {
	var pages int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/models/acme/model/discussions" {
			http.NotFound(w, r)
			return
		}
		pages++
		if r.URL.Query().Get("cursor") == "" {
			w.Header().Set("Link", `</api/models/acme/model/discussions?cursor=next>; rel="next"`)
			_, _ = w.Write([]byte(`{"discussions":[{"num":1,"title":"first","isPullRequest":false}],"count":2}`))
			return
		}
		_, _ = w.Write([]byte(`{"discussions":[{"num":2,"title":"second","isPullRequest":true}],"count":2}`))
	}))
	defer server.Close()

	src := &HuggingFace{
		baseURL:    mustParseURL(t, server.URL+"/"),
		restRetry:  httpclient.NewRetryTransport(nil),
		httpClient: http.DefaultClient,
	}
	got, err := src.listDiscussions(context.Background(), huggingFaceRepo{Kind: HuggingFaceRepoKindModel, Owner: "acme", Name: "model"})
	if err != nil {
		t.Fatalf("listDiscussions: %v", err)
	}
	if pages != 2 {
		t.Fatalf("got %d pages, want 2", pages)
	}
	if len(got) != 2 {
		t.Fatalf("got %d discussions: %+v", len(got), got)
	}
	if got[0].Num != 1 || got[0].Title != "first" || got[0].IsPullRequest {
		t.Fatalf("unexpected first discussion: %+v", got[0])
	}
	if got[1].Num != 2 || got[1].Title != "second" || !got[1].IsPullRequest {
		t.Fatalf("unexpected second discussion: %+v", got[1])
	}
}

func TestHuggingFaceEmitDiscussionEvents(t *testing.T) {
	src := &HuggingFace{baseURL: mustParseURL(t, "https://huggingface.co/")}
	repo := huggingFaceRepo{Kind: HuggingFaceRepoKindModel, Owner: "acme", Name: "model"}
	detail := huggingFaceDiscussionDetails{Num: 7, IsPullRequest: true}
	detail.Events = []huggingFaceDiscussionEvent{{ID: "abc"}}
	detail.Events[0].Data.Latest.Raw = "token=AKIALALEMEL33243OLIA"
	detail.Events[0].Author = map[string]any{"name": "alice"}

	var fragments []Fragment
	err := src.emitDiscussionEvents(context.Background(), repo, detail, func(fragment Fragment, err error) error {
		if err != nil {
			return err
		}
		fragments = append(fragments, fragment)
		return nil
	})
	if err != nil {
		t.Fatalf("emitDiscussionEvents: %v", err)
	}
	if len(fragments) != 1 {
		t.Fatalf("got %d fragments", len(fragments))
	}
	if fragments[0].Attr(AttrResource) != ResourceHuggingFaceComment {
		t.Fatalf("resource = %q", fragments[0].Attr(AttrResource))
	}
	if fragments[0].Attr(AttrHuggingFaceCommunityResource) != ResourceHuggingFacePR {
		t.Fatalf("community resource = %q", fragments[0].Attr(AttrHuggingFaceCommunityResource))
	}
	if fragments[0].Attr(AttrHuggingFaceAuthor) != "alice" {
		t.Fatalf("author = %q", fragments[0].Attr(AttrHuggingFaceAuthor))
	}
}

func TestHuggingFaceIsExcluded(t *testing.T) {
	src := &HuggingFace{ExcludeRepos: []string{"acme/test-*", "OTHER/abandoned"}}
	cases := map[string]bool{
		"acme/test-model":  true,
		"other/abandoned":  true,
		"acme/keep":        false,
		"someone/anything": false,
	}
	for name, want := range cases {
		if got := src.isExcluded(name); got != want {
			t.Fatalf("isExcluded(%q) = %v, want %v", name, got, want)
		}
	}
}

func serverURL(r *http.Request) string {
	return "http://" + r.Host
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
