package scm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/betterleaks/betterleaks/v2/internal/urlredact"
	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/config"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/client"
	"github.com/go-git/go-git/v6/plumbing/transport"
	githttp "github.com/go-git/go-git/v6/plumbing/transport/http"
	"github.com/go-git/go-git/v6/storage/filesystem"
)

// CloneOptions controls which refs are fetched into a bare repository. The zero
// value fetches branches, tags and notes, with their full history.
type CloneOptions struct {
	// Refs adds fully qualified refs or patterns containing at most one '*'.
	// Source and destination names are identical; refspec remapping is not accepted.
	Refs []string
	// AllRefs fetches every advertised ref under refs/, including review refs,
	// and subsumes Refs.
	AllRefs bool
}

func (o CloneOptions) Validate() error {
	for _, ref := range o.Refs {
		if !strings.HasPrefix(ref, "refs/") || strings.Count(ref, "*") > 1 ||
			plumbing.ReferenceName(strings.ReplaceAll(ref, "*", "x")).Validate() != nil {
			return fmt.Errorf("invalid clone ref %q: use a fully qualified refs/... name or pattern with at most one '*', without refspec remapping", ref)
		}
	}
	return nil
}

func (o CloneOptions) refSpecs() []config.RefSpec {
	if o.AllRefs {
		return []config.RefSpec{"+refs/*:refs/*"}
	}
	refs := []config.RefSpec{"+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*", "+refs/notes/*:refs/notes/*"}
	for _, ref := range o.Refs {
		spec := config.RefSpec("+" + ref + ":" + ref)
		if !slices.Contains(refs, spec) {
			refs = append(refs, spec)
		}
	}
	return refs
}

// CloneAuthed fetches the refs opts selects from an HTTP(S) repository into a
// bare repository at dest, directly in Go. Unless opts adds them, host review
// refs such as refs/pull are excluded. It does not check out files, run
// credential helpers, recurse into submodules, or execute Git/SSH.
func CloneAuthed(ctx context.Context, remote, token, dest string, opts CloneOptions) error {
	if err := opts.Validate(); err != nil {
		return err
	}
	u, err := url.Parse(remote)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errors.New("git clone requires an HTTP(S) URL without credentials, query or fragment; use Token for authentication")
	}
	if dest == "" {
		return errors.New("git clone destination is empty")
	}
	// Like git clone, never mix a clone with existing content: the scan walks
	// every ref it finds there, including ones this fetch would exclude.
	if entries, err := os.ReadDir(dest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("git clone destination: %w", err)
	} else if len(entries) > 0 {
		return errors.New("git clone destination is not empty")
	}
	if token != "" && u.Scheme != "https" {
		return errors.New("git clone tokens require HTTPS")
	}
	options := cloneHTTPClient()
	if token != "" {
		options = append(options, client.WithHTTPAuth(&githttp.BasicAuth{Username: "x-access-token", Password: token}))
	}
	if err := fetchRefs(ctx, remote, dest, opts.refSpecs(), options); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("git clone %s: %s", urlredact.Public(u), SanitizeOutput(err.Error(), token))
	}
	return nil
}

// cloneHTTPClient is go-git's default client limited to HTTP/1.1. A pack arrives
// as one long response, which HTTP/2 cannot multiplex, and Go's HTTP/2 client
// was slower at it: downloading kubernetes from GitHub took 35 s with the
// default stream window and 27 s with a 64 MiB one, against 23 s over HTTP/1.1.
// go-git still applies its redirect and credential policy to this client.
//
//nolint:exhaustruct // Unset client fields keep net/http's defaults.
func cloneHTTPClient() []client.Option {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil
	}
	tr := base.Clone()
	tr.Protocols = new(http.Protocols)
	tr.Protocols.SetHTTP1(true)
	// Clone copies the TLS config after setting up HTTP/2 on the original, so it
	// would still offer h2 to the server, which would then expect HTTP/2.
	if tr.TLSClientConfig != nil {
		tr.TLSClientConfig.NextProtos = nil
	}
	return []client.Option{client.WithHTTPClient(&http.Client{Transport: tr})}
}

// fetchRefs selects refs before downloading their objects.
//
//nolint:exhaustruct // Unset go-git options keep their defaults.
func fetchRefs(ctx context.Context, remote, dest string, refs []config.RefSpec, options []client.Option) error {
	repo, err := git.PlainInit(dest, true)
	if err != nil {
		return err
	}
	storage := &packStorage{Storage: repo.Storer.(*filesystem.Storage), ctx: ctx,
		dir: filepath.Join(dest, "objects", "pack"), limits: fetchPackLimits()}
	repo.Storer = storage
	defer storage.Close()
	origin, err := repo.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{remote}, Fetch: refs})
	if err != nil {
		return err
	}
	advertised, err := origin.ListContext(ctx, &git.ListOptions{ClientOptions: options})
	if err != nil && !errors.Is(err, transport.ErrEmptyRemoteRepository) {
		return err
	}
	// Exact selections must exist, even on an otherwise empty remote. Patterns
	// may match nothing, like Git's wildcard fetch refspecs.
	for _, spec := range refs {
		if !spec.IsWildcard() && !slices.ContainsFunc(advertised, func(ref *plumbing.Reference) bool {
			return string(ref.Name()) == spec.Src()
		}) {
			return fmt.Errorf("%w: %s", git.ErrRemoteRefNotFound, spec.Src())
		}
	}
	if errors.Is(err, transport.ErrEmptyRemoteRepository) {
		return nil
	}
	err = origin.FetchContext(ctx, &git.FetchOptions{RefSpecs: refs, ClientOptions: options, Tags: plumbing.NoTags})
	if errors.Is(err, transport.ErrEmptyRemoteRepository) {
		// A remote containing only excluded refs is empty for this scan.
		return nil
	}
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return err
	}
	for _, ref := range advertised {
		if ref.Name() != plumbing.HEAD {
			continue
		}
		if ref.Type() == plumbing.SymbolicReference {
			for _, spec := range refs {
				if spec.Match(ref.Target()) {
					return repo.Storer.SetReference(ref)
				}
			}
			return nil
		}
		if ref.Type() == plumbing.HashReference {
			// Preserve a detached HEAD only if the selected refs brought its
			// object with them; HEAD must not pull excluded history back in.
			if err := repo.Storer.HasEncodedObject(ref.Hash()); err != nil {
				if errors.Is(err, plumbing.ErrObjectNotFound) {
					return nil
				}
				return err
			}
			return repo.Storer.SetReference(ref)
		}
	}
	return nil
}

// CloneToTempDir clones a remote into a temporary directory, invokes fn with
// the cloned repo path, and removes the directory afterwards.
func CloneToTempDir(ctx context.Context, remote, token, tempDirPattern string, opts CloneOptions, fn func(repoPath string) error) error {
	if tempDirPattern == "" {
		tempDirPattern = "betterleaks-git-*"
	}
	tmpDir, err := os.MkdirTemp("", tempDirPattern)
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := CloneAuthed(ctx, remote, token, tmpDir, opts); err != nil {
		return err
	}
	return fn(tmpDir)
}

// SanitizeOutput redacts the token (and any URL-encoded form of it) from text.
// It also strips URL userinfo, query parameters, and fragments.
// Use it when wrapping transport errors.
func SanitizeOutput(text, token string) string {
	if text == "" {
		return text
	}
	if token != "" {
		text = strings.ReplaceAll(text, token, "***")
		if encoded := url.QueryEscape(token); encoded != token {
			text = strings.ReplaceAll(text, encoded, "***")
		}
	}
	return urlredact.Redact(text)
}
