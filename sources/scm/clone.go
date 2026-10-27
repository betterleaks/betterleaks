package scm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/betterleaks/betterleaks/v2/internal/gitfs"
	"github.com/betterleaks/betterleaks/v2/internal/gitobj"
	"github.com/betterleaks/betterleaks/v2/internal/urlredact"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/filesystem"
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
			gitobj.ValidateReferenceName(plumbing.ReferenceName(strings.ReplaceAll(ref, "*", "x"))) != nil {
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
	if options.owned {
		defer options.client.CloseIdleConnections()
	}
	if token != "" {
		options.auth = &githttp.BasicAuth{Username: "x-access-token", Password: token}
	}
	if err := fetchRefs(ctx, remote, dest, opts.refSpecs(), options); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("git clone %s: %s", urlredact.Public(u), SanitizeOutput(err.Error(), token))
	}
	return nil
}

type cloneTransport struct {
	client *http.Client
	auth   transport.AuthMethod
	owned  bool
}

// cloneHTTPClient is go-git's default client limited to HTTP/1.1. A pack arrives
// as one long response, which HTTP/2 cannot multiplex, and Go's HTTP/2 client
// was slower at it: downloading kubernetes from GitHub took 35 s with the
// default stream window and 27 s with a 64 MiB one, against 23 s over HTTP/1.1.
// go-git still applies its redirect and credential policy to this client.
//
//nolint:exhaustruct // Unset client fields keep net/http's defaults.
func cloneHTTPClient() cloneTransport {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return cloneTransport{client: &http.Client{Transport: http.DefaultTransport}, auth: nil, owned: false}
	}
	tr := base.Clone()
	tr.Protocols = new(http.Protocols)
	tr.Protocols.SetHTTP1(true)
	// Clone copies the TLS config after setting up HTTP/2 on the original, so it
	// would still offer h2 to the server, which would then expect HTTP/2.
	if tr.TLSClientConfig != nil {
		tr.TLSClientConfig.NextProtos = nil
	}
	return cloneTransport{client: &http.Client{Transport: tr}, auth: nil, owned: true}
}

// fetchRefs selects refs before downloading their objects.
//
//nolint:exhaustruct // Unset go-git options keep their defaults.
func fetchRefs(ctx context.Context, remote, dest string, refs []config.RefSpec, options cloneTransport) error {
	repo, err := git.PlainInit(dest, true)
	if err != nil {
		return err
	}
	storage := &packStorage{Storage: repo.Storer.(*filesystem.Storage), ctx: ctx,
		dir: filepath.Join(dest, "objects", "pack"), limits: fetchPackLimits()}
	defer storage.Close()
	if _, err := repo.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{remote}, Fetch: refs}); err != nil {
		return err
	}
	endpoint, err := transport.NewEndpoint(remote)
	if err != nil {
		return err
	}
	client := githttp.NewClient(options.client)
	session, err := client.NewUploadPackSession(endpoint, options.auth)
	if err != nil {
		return err
	}
	defer session.Close()
	advertised, err := session.AdvertisedReferencesContext(ctx)
	if err != nil && !errors.Is(err, transport.ErrEmptyRemoteRepository) {
		return err
	}
	for _, spec := range refs {
		if !spec.IsWildcard() && (advertised == nil || advertised.References[spec.Src()].IsZero()) {
			return fmt.Errorf("remote ref not found: %s", spec.Src())
		}
	}
	if advertised == nil || errors.Is(err, transport.ErrEmptyRemoteRepository) {
		return nil
	}
	selected := make(map[string]plumbing.Hash)
	want := make(map[plumbing.Hash]struct{})
	for name, id := range advertised.References {
		if !strings.HasPrefix(name, "refs/") || strings.HasSuffix(name, "^{}") {
			continue
		}
		for _, spec := range refs {
			if spec.Match(plumbing.ReferenceName(name)) {
				selected[name] = id
				want[id] = struct{}{}
				break
			}
		}
	}
	if len(want) == 0 {
		return nil
	}
	request := packp.NewUploadPackRequest()
	for id := range want {
		request.Wants = append(request.Wants, id)
	}
	plumbing.HashesSort(request.Wants)
	// With no progress consumer, request the raw pack stream, matching the v6
	// source's protocol-v0 path. Protocol v2 uses different framing.
	for _, cap := range []capability.Capability{capability.OFSDelta, capability.NoProgress} {
		if advertised.Capabilities.Supports(cap) {
			if err := request.Capabilities.Set(cap); err != nil {
				return err
			}
		}
	}
	response, err := session.UploadPack(ctx, request)
	if err != nil {
		return err
	}
	defer response.Close()
	writer, err := storage.PackfileWriter()
	if err != nil {
		return err
	}
	copied, copyErr := io.Copy(writer, response)
	if copyErr == nil && copied == 0 {
		// A fresh clone with nonempty wants needs a pack. A protocol ACK/NAK
		// alone is not a successful fetch, even though the reader reaches EOF.
		copyErr = fmt.Errorf("remote returned no pack for requested objects: %w", io.ErrUnexpectedEOF)
	}
	if copyErr != nil {
		writer.(*packWriter).err = copyErr
	}
	if err := errors.Join(copyErr, writer.Close()); err != nil {
		return err
	}
	for name, id := range selected {
		if err := storage.SetReference(plumbing.NewHashReference(plumbing.ReferenceName(name), id)); err != nil {
			return err
		}
	}
	for _, sym := range advertised.Capabilities.Get(capability.SymRef) {
		if target, ok := strings.CutPrefix(sym, "HEAD:"); ok {
			if _, exists := selected[target]; exists {
				return storage.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, plumbing.ReferenceName(target)))
			}
			return nil
		}
	}
	if advertised.Head != nil {
		// Preserve detached HEAD only when its object was fetched.
		if err := hasFetchedObject(ctx, storage.dir, *advertised.Head); err == nil {
			return storage.SetReference(plumbing.NewHashReference(plumbing.HEAD, *advertised.Head))
		} else if !errors.Is(err, plumbing.ErrObjectNotFound) {
			return err
		}
	}
	return nil
}

// The destination was empty before fetching, so all of its objects are packed.
// Checking detached HEAD through v5's filesystem store would eagerly decode
// the entire index; reuse the scanner's lazy index for this single lookup.
func hasFetchedObject(ctx context.Context, dir string, id plumbing.Hash) error {
	fs := gitfs.New(dir, gitfs.WithMmap())
	entries, err := fs.ReadDir(".")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "pack-") || !strings.HasSuffix(name, ".idx") {
			continue
		}
		packID := strings.TrimSuffix(strings.TrimPrefix(name, "pack-"), ".idx")
		if !gitobj.IsHash(packID) {
			return errors.New("invalid fetched pack index filename")
		}
		file, err := fs.Open(name)
		if err != nil {
			return err
		}
		idx, err := gitobj.OpenIndex(ctx, file, nil, gitobj.NewHash(packID))
		if err != nil {
			file.Close()
			return err
		}
		_, err = idx.FindOffset(gitobj.NewHash(id.String()))
		closeErr := idx.Close()
		if closeErr != nil {
			return errors.Join(err, closeErr)
		}
		if !errors.Is(err, plumbing.ErrObjectNotFound) {
			return err
		}
	}
	return plumbing.ErrObjectNotFound
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
