package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/semgroup"
	"golang.org/x/sync/errgroup"

	"github.com/betterleaks/betterleaks/internal/httpclient"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources/scm"
)

const (
	huggingFaceDefaultBase                      = "https://huggingface.co/"
	huggingFacePerPage                          = 100
	huggingFaceScanConcurrency                  = 100
	huggingFaceAPIConcurrency                   = 10
	huggingFaceSnippetLimit                     = 200
	huggingFaceBucketWorkers                    = 16
	huggingFaceLargeObjectWarnThreshold   int64 = 1024 * 1024 * 1024
	huggingFaceDefaultMaxBucketObjectSize int64 = 250 * 1024 * 1024
)

// HuggingFace enumerates Hugging Face model, dataset, and Space repositories
// via the Hub API and delegates git history scanning to the Git source.
type HuggingFace struct {
	Token string
	URL   string

	Include      []string
	Exclude      []string
	ExcludeRepos []string // glob patterns matched against "owner/name"
	Resources    HuggingFaceResourceSet

	ShouldSkip      SkipFunc
	Sema            *semgroup.Group
	MaxArchiveDepth int
	Workers         int
	LogOpts         string

	MaxBucketObjectSize int64

	httpClient *http.Client
	restRetry  *httpclient.RetryTransport
	baseURL    *url.URL
	apiSem     chan struct{}
}

type HuggingFaceResourceType string

const (
	HuggingFaceResourceTypeRepos       HuggingFaceResourceType = "repos"
	HuggingFaceResourceTypeDiscussions HuggingFaceResourceType = "discussions"
	HuggingFaceResourceTypePRs         HuggingFaceResourceType = "prs"
	HuggingFaceResourceTypeBuckets     HuggingFaceResourceType = "buckets"
)

var AllHuggingFaceResourceTypes = []HuggingFaceResourceType{
	HuggingFaceResourceTypeRepos,
	HuggingFaceResourceTypeDiscussions,
	HuggingFaceResourceTypePRs,
	HuggingFaceResourceTypeBuckets,
}

type HuggingFaceResourceSet map[HuggingFaceResourceType]bool

func (rs HuggingFaceResourceSet) Has(r HuggingFaceResourceType) bool { return rs[r] }

func (rs HuggingFaceResourceSet) String() string {
	var out []string
	for rt := range rs {
		out = append(out, string(rt))
	}
	return strings.Join(out, ",")
}

// Validate checks the Hugging Face source configuration and resolves default
// resource selection.
func (s *HuggingFace) Validate() error {
	if s.URL == "" {
		return errors.New("target URL is required")
	}
	if _, err := ParseHuggingFaceURL(s.URL); err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	if len(s.Resources) == 0 {
		valid := make(map[HuggingFaceResourceType]bool, len(AllHuggingFaceResourceTypes))
		for _, rt := range AllHuggingFaceResourceTypes {
			valid[rt] = true
		}
		target, err := ParseHuggingFaceURL(s.URL)
		if err != nil {
			return fmt.Errorf("invalid target URL: %w", err)
		}
		rs := HuggingFaceResourceSet{HuggingFaceResourceTypeRepos: true}
		if target.Kind == "bucket" {
			rs = HuggingFaceResourceSet{HuggingFaceResourceTypeBuckets: true}
		}
		for _, name := range s.Include {
			rt := HuggingFaceResourceType(name)
			if !valid[rt] {
				return fmt.Errorf("unknown resource type %q", name)
			}
			rs[rt] = true
		}
		for _, name := range s.Exclude {
			rt := HuggingFaceResourceType(name)
			if !valid[rt] {
				return fmt.Errorf("unknown resource type %q", name)
			}
			delete(rs, rt)
		}
		s.Resources = rs
	}
	return nil
}

func (s *HuggingFace) Fragments(ctx context.Context, yield FragmentsFunc) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if err := s.ensureClient(); err != nil {
		return err
	}
	logging.Info().
		Str("target", s.URL).
		Stringer("resources", s.Resources).
		Msg("starting Hugging Face scan")

	start := time.Now()
	target, err := ParseHuggingFaceURL(s.URL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	scanCtx, cancelScans := context.WithCancel(ctx)
	defer cancelScans()

	var scanGroup errgroup.Group
	scanGroup.SetLimit(huggingFaceScanConcurrency)

	var repoCount atomic.Int64
	var bucketCount atomic.Int64
	wantsRepoScan := target.Kind != "bucket" &&
		(s.Resources.Has(HuggingFaceResourceTypeRepos) ||
			s.Resources.Has(HuggingFaceResourceTypeDiscussions) ||
			s.Resources.Has(HuggingFaceResourceTypePRs))
	if wantsRepoScan {
		repoCh, enumErrCh := s.enumerateRepos(ctx, target)
		for repo := range repoCh {
			repoCount.Add(1)
			scanGroup.Go(func() error {
				return s.scanRepo(scanCtx, repo, yield)
			})
		}
		enumErr := <-enumErrCh
		if enumErr != nil {
			cancelScans()
			scanErr := scanGroup.Wait()
			combined := fmt.Errorf("enumerate Hugging Face repos: %w", enumErr)
			if scanErr != nil && !errors.Is(scanErr, context.Canceled) {
				combined = errors.Join(combined, scanErr)
			}
			return combined
		}
	}

	if s.Resources.Has(HuggingFaceResourceTypeBuckets) {
		bucketCh, bucketErrCh := s.enumerateBuckets(ctx, target)
		for bucket := range bucketCh {
			bucketCount.Add(1)
			scanGroup.Go(func() error {
				return s.scanBucket(scanCtx, bucket, yield)
			})
		}
		enumErr := <-bucketErrCh
		if enumErr != nil {
			cancelScans()
			scanErr := scanGroup.Wait()
			combined := fmt.Errorf("enumerate Hugging Face buckets: %w", enumErr)
			if scanErr != nil && !errors.Is(scanErr, context.Canceled) {
				combined = errors.Join(combined, scanErr)
			}
			return combined
		}
	}
	logging.Info().
		Int64("repos", repoCount.Load()).
		Int64("buckets", bucketCount.Load()).
		Dur("enumeration_ms", time.Since(start)).
		Msg("enumeration complete, waiting for scans")

	scanErr := scanGroup.Wait()
	logging.Info().
		Int64("repos", repoCount.Load()).
		Int64("buckets", bucketCount.Load()).
		Dur("duration", time.Since(start)).
		Msg("scan complete")
	return scanErr
}

type HuggingFaceRepoKind string

const (
	HuggingFaceRepoKindModel   HuggingFaceRepoKind = "model"
	HuggingFaceRepoKindDataset HuggingFaceRepoKind = "dataset"
	HuggingFaceRepoKindSpace   HuggingFaceRepoKind = "space"
)

type ParsedHuggingFaceURL struct {
	Scheme string
	Host   string
	Kind   string // "owner" or "repo"
	Owner  string
	Name   string
	Type   HuggingFaceRepoKind
	Prefix string
}

func ParseHuggingFaceURL(rawURL string) (*ParsedHuggingFaceURL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme == "hf" {
		segments := cleanPathSegments(u.Host + "/" + u.Path)
		if len(segments) < 3 || segments[0] != "buckets" {
			return nil, fmt.Errorf("hf:// URL must use hf://buckets/<owner>/<bucket>[/prefix]")
		}
		return &ParsedHuggingFaceURL{
			Scheme: "hf",
			Host:   "buckets",
			Kind:   "bucket",
			Owner:  segments[1],
			Name:   segments[2],
			Prefix: strings.Join(segments[3:], "/"),
		}, nil
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("URL must use http or https scheme")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("URL must include a host")
	}
	segments := cleanPathSegments(u.Path)
	out := &ParsedHuggingFaceURL{Scheme: u.Scheme, Host: strings.ToLower(u.Host)}
	switch {
	case len(segments) >= 3 && segments[0] == "buckets":
		out.Kind = "bucket"
		out.Owner = segments[1]
		out.Name = segments[2]
		out.Prefix = strings.Join(segments[3:], "/")
		return out, nil
	case len(segments) == 1:
		out.Kind = "owner"
		out.Owner = segments[0]
		return out, nil
	case len(segments) >= 3 && segments[0] == "datasets":
		out.Kind = "repo"
		out.Type = HuggingFaceRepoKindDataset
		out.Owner = segments[1]
		out.Name = strings.TrimSuffix(strings.Join(segments[2:], "/"), ".git")
	case len(segments) >= 3 && segments[0] == "spaces":
		out.Kind = "repo"
		out.Type = HuggingFaceRepoKindSpace
		out.Owner = segments[1]
		out.Name = strings.TrimSuffix(strings.Join(segments[2:], "/"), ".git")
	case len(segments) >= 2:
		out.Kind = "repo"
		out.Type = HuggingFaceRepoKindModel
		out.Owner = segments[0]
		out.Name = strings.TrimSuffix(strings.Join(segments[1:], "/"), ".git")
	default:
		return nil, fmt.Errorf("Hugging Face URL must identify an owner or repository")
	}
	if out.Owner == "" || out.Name == "" {
		return nil, fmt.Errorf("Hugging Face repository URL must include owner and name")
	}
	return out, nil
}

func cleanPathSegments(p string) []string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	out := parts[:0]
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

type huggingFaceRepo struct {
	Kind       HuggingFaceRepoKind
	Owner      string
	Name       string
	Visibility string
}

func (r huggingFaceRepo) Slug() string { return r.Owner + "/" + r.Name }

func (r huggingFaceRepo) CanonicalKey() string {
	return string(r.Kind) + ":" + strings.ToLower(r.Slug())
}

func (r huggingFaceRepo) WebURL(base *url.URL) string {
	u := *base
	switch r.Kind {
	case HuggingFaceRepoKindDataset:
		u.Path = singleSlashJoin(u.Path, "datasets/"+r.Slug())
	case HuggingFaceRepoKindSpace:
		u.Path = singleSlashJoin(u.Path, "spaces/"+r.Slug())
	default:
		u.Path = singleSlashJoin(u.Path, r.Slug())
	}
	u.RawQuery = ""
	return u.String()
}

func (r huggingFaceRepo) GitURL(base *url.URL) string {
	return strings.TrimSuffix(r.WebURL(base), "/") + ".git"
}

func (s *HuggingFace) enumerateRepos(ctx context.Context, target *ParsedHuggingFaceURL) (<-chan huggingFaceRepo, <-chan error) {
	ch := make(chan huggingFaceRepo, 100)
	errCh := make(chan error, 1)
	go func() {
		defer close(ch)
		defer close(errCh)
		seen := make(map[string]bool)
		send := func(repo huggingFaceRepo) bool {
			if repo.Owner == "" || repo.Name == "" {
				return true
			}
			key := repo.CanonicalKey()
			if seen[key] {
				return true
			}
			if s.isExcluded(repo.Slug()) {
				logging.Debug().Str("repo", repo.Slug()).Str("type", string(repo.Kind)).Msg("excluding Hugging Face repo")
				return true
			}
			seen[key] = true
			select {
			case ch <- repo:
				return true
			case <-ctx.Done():
				return false
			}
		}

		if target.Kind == "repo" {
			send(huggingFaceRepo{Kind: target.Type, Owner: target.Owner, Name: target.Name})
			errCh <- nil
			return
		}

		for _, kind := range []HuggingFaceRepoKind{HuggingFaceRepoKindModel, HuggingFaceRepoKindDataset, HuggingFaceRepoKindSpace} {
			logging.Info().
				Str("owner", target.Owner).
				Str("type", string(kind)).
				Msg("enumerating Hugging Face repositories")
			repos, err := s.listReposByAuthor(ctx, kind, target.Owner)
			if err != nil {
				errCh <- fmt.Errorf("list %s repos for %s: %w", kind, target.Owner, err)
				return
			}
			logging.Info().
				Str("owner", target.Owner).
				Str("type", string(kind)).
				Int("repos", len(repos)).
				Msg("Hugging Face repository enumeration complete")
			for _, repo := range repos {
				if !send(repo) {
					errCh <- ctx.Err()
					return
				}
			}
		}
		errCh <- nil
	}()
	return ch, errCh
}

type huggingFaceBucket struct {
	Owner      string
	Name       string
	Prefix     string
	Private    bool
	Size       int64
	TotalFiles int64
}

func (b huggingFaceBucket) ID() string { return b.Owner + "/" + b.Name }

func (b huggingFaceBucket) WebURL(base *url.URL) string {
	u := *base
	pathValue := "buckets/" + b.ID()
	if b.Prefix != "" {
		pathValue += "/" + strings.TrimPrefix(b.Prefix, "/")
	}
	u.Path = singleSlashJoin(u.Path, pathValue)
	u.RawQuery = ""
	return u.String()
}

func (s *HuggingFace) enumerateBuckets(ctx context.Context, target *ParsedHuggingFaceURL) (<-chan huggingFaceBucket, <-chan error) {
	ch := make(chan huggingFaceBucket, 100)
	errCh := make(chan error, 1)
	go func() {
		defer close(ch)
		defer close(errCh)
		send := func(bucket huggingFaceBucket) bool {
			if s.isExcluded(bucket.ID()) {
				logging.Debug().Str("bucket", bucket.ID()).Msg("excluding Hugging Face bucket")
				return true
			}
			logging.Trace().
				Str("bucket", bucket.ID()).
				Str("prefix", bucket.Prefix).
				Msg("queueing Hugging Face bucket scan")
			select {
			case ch <- bucket:
				return true
			case <-ctx.Done():
				return false
			}
		}

		if target.Kind == "bucket" {
			send(huggingFaceBucket{Owner: target.Owner, Name: target.Name, Prefix: target.Prefix})
			errCh <- nil
			return
		}
		if target.Kind != "owner" {
			errCh <- nil
			return
		}
		logging.Info().Str("owner", target.Owner).Msg("enumerating Hugging Face buckets")
		buckets, err := s.listBuckets(ctx, target.Owner)
		if err != nil {
			errCh <- fmt.Errorf("list buckets for %s: %w", target.Owner, err)
			return
		}
		logging.Info().
			Str("owner", target.Owner).
			Int("buckets", len(buckets)).
			Msg("Hugging Face bucket enumeration complete")
		for _, bucket := range buckets {
			if !send(bucket) {
				errCh <- ctx.Err()
				return
			}
		}
		errCh <- nil
	}()
	return ch, errCh
}

type huggingFaceBucketInfo struct {
	ID         string `json:"id"`
	Private    bool   `json:"private"`
	Size       int64  `json:"size"`
	TotalFiles int64  `json:"total_files"`
}

func (s *HuggingFace) listBuckets(ctx context.Context, namespace string) ([]huggingFaceBucket, error) {
	if namespace == "" {
		namespace = "me"
	}
	u, err := s.apiURL("buckets/" + escapePathSegments(namespace))
	if err != nil {
		return nil, err
	}
	var buckets []huggingFaceBucket
	err = s.paginateJSON(ctx, u, func(body []byte) error {
		var page []huggingFaceBucketInfo
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("decode buckets: %w; body snippet: %s", err, snippet(body))
		}
		for _, item := range page {
			owner, name, ok := splitOwnerName(item.ID)
			if !ok {
				logging.Warn().Str("bucket", item.ID).Msg("skipping Hugging Face bucket with unexpected identifier")
				continue
			}
			buckets = append(buckets, huggingFaceBucket{
				Owner:      owner,
				Name:       name,
				Private:    item.Private,
				Size:       item.Size,
				TotalFiles: item.TotalFiles,
			})
		}
		return nil
	})
	return buckets, err
}

func splitOwnerName(id string) (owner, name string, ok bool) {
	owner, name, ok = strings.Cut(strings.Trim(id, "/"), "/")
	return owner, name, ok && owner != "" && name != ""
}

type huggingFaceListItem struct {
	ID         string `json:"id"`
	ModelID    string `json:"modelId"`
	Private    bool   `json:"private"`
	IsPrivate  bool   `json:"isPrivate"`
	Visibility string `json:"visibility"`
}

func (i huggingFaceListItem) identifier() string {
	if i.ID != "" {
		return i.ID
	}
	return i.ModelID
}

func (i huggingFaceListItem) visibility() string {
	if i.Visibility != "" {
		return i.Visibility
	}
	if i.Private || i.IsPrivate {
		return "private"
	}
	return ""
}

func (s *HuggingFace) listReposByAuthor(ctx context.Context, kind HuggingFaceRepoKind, author string) ([]huggingFaceRepo, error) {
	u, err := s.apiURL(kind.apiPath())
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("author", author)
	q.Set("limit", strconv.Itoa(huggingFacePerPage))
	u.RawQuery = q.Encode()

	var repos []huggingFaceRepo
	err = s.paginateJSON(ctx, u, func(body []byte) error {
		var page []huggingFaceListItem
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("decode %s list: %w; body snippet: %s", kind, err, snippet(body))
		}
		for idx, item := range page {
			owner, name, ok := parseHuggingFaceSlug(kind, item.identifier())
			if !ok {
				logging.Warn().Int("index", idx).Str("identifier", item.identifier()).Msg("skipping Hugging Face item with unexpected identifier")
				continue
			}
			repos = append(repos, huggingFaceRepo{
				Kind:       kind,
				Owner:      owner,
				Name:       name,
				Visibility: item.visibility(),
			})
			logging.Trace().
				Str("owner", owner).
				Str("repo", name).
				Str("type", string(kind)).
				Msg("discovered Hugging Face repository")
		}
		return nil
	})
	return repos, err
}

func parseHuggingFaceSlug(kind HuggingFaceRepoKind, raw string) (owner, name string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		parsed, err := ParseHuggingFaceURL(raw)
		if err != nil || parsed.Kind != "repo" || parsed.Type != kind {
			return "", "", false
		}
		return parsed.Owner, parsed.Name, true
	}
	parts := cleanPathSegments(raw)
	if len(parts) > 0 {
		switch kind {
		case HuggingFaceRepoKindDataset:
			if parts[0] == "datasets" || parts[0] == "dataset" {
				parts = parts[1:]
			}
		case HuggingFaceRepoKindSpace:
			if parts[0] == "spaces" || parts[0] == "space" {
				parts = parts[1:]
			}
		case HuggingFaceRepoKindModel:
			if parts[0] == "models" || parts[0] == "model" {
				parts = parts[1:]
			}
		}
	}
	if len(parts) < 2 {
		return "", "", false
	}
	owner = strings.TrimSpace(parts[0])
	name = strings.TrimSuffix(strings.Join(parts[1:], "/"), ".git")
	return owner, name, owner != "" && name != ""
}

func (s *HuggingFace) scanRepo(ctx context.Context, repo huggingFaceRepo, yield FragmentsFunc) error {
	logger := logging.With().Str("repo", repo.Slug()).Str("type", string(repo.Kind)).Logger()
	repoAttrs := s.repoAttributes(repo, "")
	if s.ShouldSkip != nil && s.ShouldSkip(s.repoAttributes(repo, ResourceHuggingFaceRepo)) {
		logger.Debug().Msg("skipping Hugging Face repository based on prefilter")
		return nil
	}
	hfYield := s.wrapYieldWithAttrs(repoAttrs, yield)

	run := func(label string, fn func() error) error {
		logger.Info().Str("resource", label).Msg("scanning")
		if err := fn(); err != nil {
			logger.Error().Err(err).Msg(label + " scan failed")
			return err
		}
		logger.Info().Str("resource", label).Msg("completed")
		return nil
	}

	if s.Resources.Has(HuggingFaceResourceTypeRepos) {
		if err := run(string(HuggingFaceResourceTypeRepos), func() error {
			return s.scanRepoGit(ctx, repo, hfYield)
		}); err != nil {
			return err
		}
	}
	if s.Resources.Has(HuggingFaceResourceTypeDiscussions) || s.Resources.Has(HuggingFaceResourceTypePRs) {
		if err := run("community", func() error { return s.scanCommunity(ctx, repo, hfYield) }); err != nil {
			return err
		}
	}
	return nil
}

func (s *HuggingFace) repoAttributes(repo huggingFaceRepo, resource string) map[string]string {
	attrs := map[string]string{
		AttrHuggingFaceOwner:      repo.Owner,
		AttrHuggingFaceRepo:       repo.Name,
		AttrHuggingFaceRepoType:   string(repo.Kind),
		AttrHuggingFaceRepoURL:    repo.WebURL(s.baseURL),
		AttrHuggingFaceVisibility: repo.Visibility,
	}
	if resource != "" {
		attrs[AttrResource] = resource
	}
	return attrs
}

func (s *HuggingFace) wrapYieldWithAttrs(attrs map[string]string, yield FragmentsFunc) FragmentsFunc {
	var mu sync.Mutex
	return func(fragment Fragment, err error) error {
		if err == nil {
			for k, v := range attrs {
				if v == "" || fragment.Attr(k) != "" {
					continue
				}
				fragment.SetAttr(k, v)
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

func (s *HuggingFace) scanRepoGit(ctx context.Context, repo huggingFaceRepo, yield FragmentsFunc) error {
	remote := repo.GitURL(s.baseURL)
	return scm.CloneToTempDir(ctx, remote, s.Token, "betterleaks-huggingface-*", scm.CloneOptions{Mirror: true}, func(repoPath string) error {
		var src Source
		if s.Workers > 0 {
			src = &ParallelGit{
				RepoPath: repoPath, ShouldSkip: s.ShouldSkip,
				Platform: scm.UnknownPlatform, RemoteURL: repo.WebURL(s.baseURL),
				Sema: s.Sema, MaxArchiveDepth: s.MaxArchiveDepth,
				LogOpts: s.LogOpts, Workers: s.Workers,
			}
		} else {
			gitCmd, err := NewGitLogCmdContext(ctx, repoPath, s.LogOpts)
			if err != nil {
				return err
			}
			src = &Git{
				Cmd: gitCmd, ShouldSkip: s.ShouldSkip,
				Platform: scm.UnknownPlatform, RemoteURL: repo.WebURL(s.baseURL),
				Sema: s.Sema, MaxArchiveDepth: s.MaxArchiveDepth,
			}
		}
		return src.Fragments(ctx, yield)
	})
}

type huggingFaceBucketEntry struct {
	Type         string `json:"type"`
	Path         string `json:"path"`
	Size         int64  `json:"size"`
	LastModified string `json:"lastModified"`
	XetHash      string `json:"xetHash"`
}

func (s *HuggingFace) scanBucket(ctx context.Context, bucket huggingFaceBucket, yield FragmentsFunc) error {
	logger := logging.With().Str("bucket", bucket.ID()).Logger()
	logger.Info().Str("prefix", bucket.Prefix).Msg("scanning Hugging Face bucket")
	if s.ShouldSkip != nil && s.ShouldSkip(s.bucketAttributes(bucket, nil, ResourceHuggingFaceBucket)) {
		logger.Debug().Msg("skipping Hugging Face bucket based on prefilter")
		return nil
	}
	entries, err := s.listBucketTree(ctx, bucket)
	if err != nil {
		return err
	}
	maxSize := s.MaxBucketObjectSize
	if maxSize <= 0 {
		maxSize = huggingFaceDefaultMaxBucketObjectSize
	}
	workers := huggingFaceBucketWorkers
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(workers)
	var scanned atomic.Int64
	var queued int
	var skippedOversized int
	var skippedPrefilter int
	for _, entry := range entries {
		if entry.Type != "file" || entry.Path == "" {
			continue
		}
		if maxSize > 0 && entry.Size > maxSize {
			logging.Debug().
				Str("bucket", bucket.ID()).
				Str("path", entry.Path).
				Int64("size", entry.Size).
				Int64("max_size", maxSize).
				Msg("skipping oversized Hugging Face bucket object")
			skippedOversized++
			continue
		}
		if s.ShouldSkip != nil && s.ShouldSkip(s.bucketAttributes(bucket, &entry, ResourceHuggingFaceBucket)) {
			logging.Trace().
				Str("bucket", bucket.ID()).
				Str("path", entry.Path).
				Msg("skipping Hugging Face bucket object based on prefilter")
			skippedPrefilter++
			continue
		}
		if entry.Size > huggingFaceLargeObjectWarnThreshold {
			logging.Warn().
				Str("bucket", bucket.ID()).
				Str("path", entry.Path).
				Int64("size", entry.Size).
				Msg("downloading and scanning large Hugging Face bucket object")
		}
		entry := entry
		queued++
		logging.Trace().
			Str("bucket", bucket.ID()).
			Str("path", entry.Path).
			Int64("size", entry.Size).
			Msg("queueing Hugging Face bucket object scan")
		g.Go(func() error {
			if err := s.scanBucketObject(gctx, bucket, entry, yield); err != nil {
				return err
			}
			scanned.Add(1)
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}
	logger.Info().
		Int("queued_objects", queued).
		Int("skipped_oversized", skippedOversized).
		Int("skipped_prefilter", skippedPrefilter).
		Int64("scanned_objects", scanned.Load()).
		Msg("completed Hugging Face bucket scan")
	return nil
}

func (s *HuggingFace) listBucketTree(ctx context.Context, bucket huggingFaceBucket) ([]huggingFaceBucketEntry, error) {
	endpoint := "buckets/" + escapePathSegments(bucket.ID()) + "/tree"
	u, err := s.apiURL(endpoint)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("recursive", "true")
	if bucket.Prefix != "" {
		q.Set("prefix", bucket.Prefix)
	}
	u.RawQuery = q.Encode()

	logging.Info().
		Str("bucket", bucket.ID()).
		Str("prefix", bucket.Prefix).
		Msg("listing Hugging Face bucket tree")
	var entries []huggingFaceBucketEntry
	err = s.paginateJSON(ctx, u, func(body []byte) error {
		var page []huggingFaceBucketEntry
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("decode bucket tree: %w; body snippet: %s", err, snippet(body))
		}
		entries = append(entries, page...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	logging.Info().
		Str("bucket", bucket.ID()).
		Str("prefix", bucket.Prefix).
		Int("entries", len(entries)).
		Msg("Hugging Face bucket tree listed")
	return entries, err
}

func (s *HuggingFace) scanBucketObject(ctx context.Context, bucket huggingFaceBucket, entry huggingFaceBucketEntry, yield FragmentsFunc) error {
	attrs := s.bucketAttributes(bucket, &entry, ResourceHuggingFaceBucket)
	logging.Trace().
		Str("bucket", bucket.ID()).
		Str("path", entry.Path).
		Int64("size", entry.Size).
		Msg("downloading Hugging Face bucket object")
	return downloadAndScanSource(ctx, sourceDownloadOptions{
		URL:             s.bucketObjectURL(bucket, entry.Path),
		Path:            entry.Path,
		Attrs:           attrs,
		BearerToken:     s.Token,
		HTTPClient:      s.httpClient,
		MaxArchiveDepth: s.MaxArchiveDepth,
		ShouldSkip:      s.ShouldSkip,
		TempPattern:     "betterleaks-huggingface-bucket-*",
	}, yield)
}

func (s *HuggingFace) bucketObjectURL(bucket huggingFaceBucket, objectPath string) string {
	u := *s.baseURL
	u.Path = singleSlashJoin(u.Path, "buckets/"+escapePathSegments(bucket.ID())+"/resolve/"+escapePathSegments(strings.TrimPrefix(objectPath, "/")))
	u.RawQuery = ""
	return u.String()
}

func (s *HuggingFace) bucketAttributes(bucket huggingFaceBucket, entry *huggingFaceBucketEntry, resource string) map[string]string {
	attrs := map[string]string{
		AttrHuggingFaceOwner:     bucket.Owner,
		AttrHuggingFaceBucket:    bucket.Name,
		AttrHuggingFaceBucketURL: bucket.WebURL(s.baseURL),
	}
	if bucket.Private {
		attrs[AttrHuggingFaceVisibility] = "private"
	}
	if resource != "" {
		attrs[AttrResource] = resource
	}
	if entry != nil {
		attrs[AttrHuggingFaceBucketPath] = entry.Path
		attrs[AttrPath] = entry.Path
		attrs[AttrURL] = s.bucketObjectURL(bucket, entry.Path)
		if entry.Size > 0 {
			attrs[AttrHuggingFaceBucketSize] = strconv.FormatInt(entry.Size, 10)
		}
		if entry.LastModified != "" {
			attrs[AttrHuggingFaceBucketMTime] = entry.LastModified
		}
		if entry.XetHash != "" {
			attrs[AttrHuggingFaceBucketXetHash] = entry.XetHash
		}
	}
	return attrs
}

type huggingFaceDiscussion struct {
	Num           int    `json:"num"`
	Title         string `json:"title"`
	IsPullRequest bool   `json:"isPullRequest"`
	Author        any    `json:"author"`
}

type huggingFaceDiscussionDetails struct {
	Num           int                          `json:"num"`
	Title         string                       `json:"title"`
	IsPullRequest bool                         `json:"isPullRequest"`
	Author        any                          `json:"author"`
	Events        []huggingFaceDiscussionEvent `json:"events"`
}

type huggingFaceDiscussionEvent struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	CreatedAt string `json:"createdAt"`
	Author    any    `json:"author"`
	Data      struct {
		Latest struct {
			Raw string `json:"raw"`
		} `json:"latest"`
	} `json:"data"`
}

func (s *HuggingFace) scanCommunity(ctx context.Context, repo huggingFaceRepo, yield FragmentsFunc) error {
	discussions, err := s.listDiscussions(ctx, repo)
	if err != nil {
		return err
	}
	for _, discussion := range discussions {
		if discussion.IsPullRequest && !s.Resources.Has(HuggingFaceResourceTypePRs) {
			continue
		}
		if !discussion.IsPullRequest && !s.Resources.Has(HuggingFaceResourceTypeDiscussions) {
			continue
		}
		detail, err := s.getDiscussionDetails(ctx, repo, discussion.Num)
		if err != nil {
			return err
		}
		if err := s.emitDiscussionEvents(ctx, repo, detail, yield); err != nil {
			return err
		}
	}
	return nil
}

func (s *HuggingFace) listDiscussions(ctx context.Context, repo huggingFaceRepo) ([]huggingFaceDiscussion, error) {
	u, err := s.apiURL(repo.Kind.apiPath() + "/" + escapePathSegments(repo.Slug()) + "/discussions")
	if err != nil {
		return nil, err
	}
	var discussions []huggingFaceDiscussion
	err = s.paginateJSON(ctx, u, func(body []byte) error {
		var page struct {
			Discussions []huggingFaceDiscussion `json:"discussions"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("decode discussions: %w; body snippet: %s", err, snippet(body))
		}
		discussions = append(discussions, page.Discussions...)
		return nil
	})
	return discussions, err
}

func (s *HuggingFace) getDiscussionDetails(ctx context.Context, repo huggingFaceRepo, num int) (huggingFaceDiscussionDetails, error) {
	u, err := s.apiURL(repo.Kind.apiPath() + "/" + escapePathSegments(repo.Slug()) + "/discussions/" + strconv.Itoa(num))
	if err != nil {
		return huggingFaceDiscussionDetails{}, err
	}
	body, err := s.get(ctx, u)
	if err != nil {
		return huggingFaceDiscussionDetails{}, err
	}
	var detail huggingFaceDiscussionDetails
	if err := json.Unmarshal(body, &detail); err != nil {
		return huggingFaceDiscussionDetails{}, fmt.Errorf("decode discussion details: %w; body snippet: %s", err, snippet(body))
	}
	return detail, nil
}

func (s *HuggingFace) emitDiscussionEvents(ctx context.Context, repo huggingFaceRepo, detail huggingFaceDiscussionDetails, yield FragmentsFunc) error {
	resource := ResourceHuggingFaceDiscussion
	if detail.IsPullRequest {
		resource = ResourceHuggingFacePR
	}
	for _, event := range detail.Events {
		raw := event.Data.Latest.Raw
		if raw == "" {
			continue
		}
		attrs := s.repoAttributes(repo, ResourceHuggingFaceComment)
		attrs[AttrHuggingFaceDiscussionNumber] = strconv.Itoa(detail.Num)
		attrs[AttrHuggingFaceCommentID] = event.ID
		attrs[AttrHuggingFaceAuthor] = huggingFaceAuthorName(event.Author)
		attrs[AttrURL] = fmt.Sprintf("%s/discussions/%d#%s", strings.TrimRight(repo.WebURL(s.baseURL), "/"), detail.Num, event.ID)
		if event.ID == "" {
			attrs[AttrURL] = fmt.Sprintf("%s/discussions/%d", strings.TrimRight(repo.WebURL(s.baseURL), "/"), detail.Num)
		}
		attrs[AttrHuggingFaceCommunityResource] = resource
		fragment := Fragment{Raw: raw, Attributes: attrs}
		if s.ShouldSkip != nil && s.ShouldSkip(fragment.Attributes) {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err := yield(fragment, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func huggingFaceAuthorName(v any) string {
	switch author := v.(type) {
	case string:
		return author
	case map[string]any:
		for _, key := range []string{"name", "fullname", "username", "user"} {
			if val, ok := author[key].(string); ok {
				return val
			}
		}
	}
	return ""
}

func (k HuggingFaceRepoKind) apiPath() string {
	switch k {
	case HuggingFaceRepoKindDataset:
		return "datasets"
	case HuggingFaceRepoKindSpace:
		return "spaces"
	default:
		return "models"
	}
}

func (s *HuggingFace) ensureClient() error {
	if s.restRetry == nil {
		s.restRetry = httpclient.NewRetryTransport(nil)
	}
	if s.baseURL == nil {
		u, err := url.Parse(huggingFaceDefaultBase)
		if err != nil {
			return err
		}
		s.baseURL = u
	}
	if s.httpClient == nil {
		s.httpClient = httpclient.NewAuthenticatedClient(s.Token, s.restRetry, s.baseURL.Host)
	}
	if s.apiSem == nil {
		s.apiSem = make(chan struct{}, huggingFaceAPIConcurrency)
	}
	return nil
}

func (s *HuggingFace) apiURL(endpoint string) (*url.URL, error) {
	if err := s.ensureClient(); err != nil {
		return nil, err
	}
	endpoint = strings.TrimPrefix(endpoint, "/")
	u := *s.baseURL
	u.Path = singleSlashJoin(u.Path, "api/"+endpoint)
	u.RawQuery = ""
	return &u, nil
}

func (s *HuggingFace) acquireAPISlot(ctx context.Context) (func(), error) {
	if s.apiSem == nil {
		return func() {}, nil
	}
	select {
	case s.apiSem <- struct{}{}:
		return func() { <-s.apiSem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *HuggingFace) get(ctx context.Context, u *url.URL) ([]byte, error) {
	release, err := s.acquireAPISlot(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	logging.Trace().Str("url", u.String()).Msg("requesting Hugging Face API resource")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := fmt.Sprintf("Hugging Face API request %s failed: %s: %s", u.String(), resp.Status, snippet(body))
		if (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) && s.Token == "" {
			msg += "; set HUGGINGFACE_TOKEN or pass --token for private resources"
		}
		return nil, errors.New(msg)
	}
	return body, nil
}

func (s *HuggingFace) paginateJSON(ctx context.Context, first *url.URL, consume func([]byte) error) error {
	current := first
	for {
		release, err := s.acquireAPISlot(ctx)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			release()
			return err
		}
		logging.Trace().Str("url", current.String()).Msg("requesting Hugging Face API page")
		resp, err := s.httpClient.Do(req)
		release()
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			msg := fmt.Sprintf("Hugging Face API request %s failed: %s: %s", current.String(), resp.Status, snippet(body))
			if (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) && s.Token == "" {
				msg += "; set HUGGINGFACE_TOKEN or pass --token for private resources"
			}
			return errors.New(msg)
		}
		if err := consume(body); err != nil {
			return err
		}
		next := parseLinkNext(resp.Header.Get("Link"))
		if next == "" {
			return nil
		}
		u, err := url.Parse(next)
		if err != nil {
			return fmt.Errorf("parse next link: %w", err)
		}
		if !u.IsAbs() {
			u = current.ResolveReference(u)
		}
		if u.Scheme != current.Scheme || u.Host != current.Host {
			return fmt.Errorf("refusing Hugging Face pagination link to unexpected host %q", u.String())
		}
		current = u
	}
}

func parseLinkNext(value string) string {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		left, _, ok := strings.Cut(part, ">")
		if !ok {
			continue
		}
		return strings.TrimPrefix(strings.TrimSpace(left), "<")
	}
	return ""
}

func snippet(body []byte) string {
	text := string(body)
	if len([]rune(text)) <= huggingFaceSnippetLimit {
		return text
	}
	runes := []rune(text)
	return string(runes[:huggingFaceSnippetLimit]) + "..."
}

func (s *HuggingFace) isExcluded(fullName string) bool {
	lp := strings.ToLower(fullName)
	for _, pattern := range s.ExcludeRepos {
		if matched, _ := filepath.Match(strings.ToLower(pattern), lp); matched {
			return true
		}
	}
	return false
}

func escapePathSegments(value string) string {
	parts := cleanPathSegments(value)
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}
