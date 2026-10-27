// Package container scans all historical layers and metadata of Docker and OCI
// images without running them. It implements the standard sources.Source API.
package container

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"strconv"
	"strings"

	"github.com/betterleaks/betterleaks/v2/internal/urlredact"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Source scans each requested target. Empty Platforms selects every platform,
// including artifacts attached through an image index. Archive inputs contain
// Docker save or OCI layout tar streams; Layouts are OCI layout directories.
// Registry authentication reads Docker/Podman credential files without invoking
// credential helpers by default. CredentialHelpers explicitly enables helpers;
// Anonymous bypasses all authentication, and Keychain overrides the built-in provider.
// Daemon selects the Docker or Podman HTTP API and never pulls
// images; an empty Daemon selects registry scanning.
type Source struct {
	Images, Archives, Layouts []string
	Platforms                 []string
	Daemon                    string
	// DaemonHost overrides connection profiles and environment settings (including
	// Docker TLS). Supports unix://, npipe://, tcp://, http:// and https://. Empty
	// resolves Docker contexts or Podman JSON connections, then the local default.
	DaemonHost string
	// DaemonTransport overrides the engine transport, for example to configure
	// mutual TLS. The caller owns its lifetime. Transport below is registry-only.
	DaemonTransport      http.RoundTripper
	Anonymous, PlainHTTP bool
	// CredentialHelpers permits configured docker-credential-* executables.
	// Anonymous takes precedence; an explicit Keychain controls its own behavior.
	CredentialHelpers bool
	Keychain          authn.Keychain
	Transport         http.RoundTripper
	Logger            *slog.Logger
	Prefilter         sources.PrefilterFunc
	MaxArchiveDepth   int
	// MaxFileSize limits individual layer files (zero is unlimited). Exceeding
	// a configured limit is a source error, so reports cannot claim completeness.
	MaxFileSize int64
	// MaxArchiveSize bounds the expanded outer tar stream (including headers,
	// padding and trailing data) and extracted file bytes; zero uses 20 GiB.
	MaxArchiveSize int64
}

func (s *Source) Validate() error {
	if len(s.Images)+len(s.Archives)+len(s.Layouts) == 0 {
		return errors.New("supply an image, --archive, or --oci-layout")
	}
	if s.MaxFileSize < 0 || s.MaxArchiveSize < 0 || s.MaxArchiveDepth < 0 {
		return errors.New("container size and archive depth limits must be non-negative")
	}
	if s.Daemon != "" && s.Daemon != "docker" && s.Daemon != "podman" {
		return fmt.Errorf("invalid --daemon %q: expected docker or podman", s.Daemon)
	}
	if s.Daemon != "" && len(s.Images) == 0 {
		return errors.New("--daemon requires an image reference")
	}
	if s.Daemon == "" && (s.DaemonHost != "" || s.DaemonTransport != nil) {
		return errors.New("daemon connection options require --daemon docker or podman")
	}
	if s.DaemonHost != "" {
		if _, err := parseDaemonHost(s.DaemonHost); err != nil {
			return err
		}
	}
	for _, p := range s.Platforms {
		parts := strings.Split(p, "/")
		if len(parts) < 2 || len(parts) > 3 {
			return fmt.Errorf("invalid platform %q: expected os/architecture[/variant]", p)
		}
		for _, part := range parts {
			if part == "" {
				return fmt.Errorf("invalid platform %q", p)
			}
		}
	}
	return nil
}

type session struct {
	s *Source
	// yield reports recoverable coverage failures through its error argument.
	// Its return value only requests a stop; nil does not establish completeness.
	yield                 sources.FragmentsFunc
	stopped               error
	images, layers, files int
	selectedPlatforms     int
	manifestVisits        int
}

func (s *Source) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r := &session{s: s}
	r.yield = func(f sources.Fragment, err error) error {
		if r.stopped != nil {
			return r.stopped
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		r.stopped = yield(f, urlredact.Error(err))
		return r.stopped
	}
	visit := func(target string, fn func() error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		r.manifestVisits = 0
		before := r.selectedPlatforms
		if err := fn(); err != nil {
			if r.stopped != nil {
				return r.stopped
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return r.yield(sources.Fragment{}, fmt.Errorf("container %q: %w", target, err))
		}
		if len(s.Platforms) > 0 && before == r.selectedPlatforms {
			return r.yield(sources.Fragment{}, fmt.Errorf("container %q: no runtime image matches requested platforms", target))
		}
		return nil
	}
	for _, ref := range s.Images {
		if err := visit(ref, func() error {
			if s.Daemon != "" {
				return r.daemon(ctx, ref)
			}
			return r.registry(ctx, ref)
		}); err != nil {
			return err
		}
	}
	for _, file := range s.Archives {
		if err := visit(file, func() error { return r.archive(ctx, file) }); err != nil {
			return err
		}
	}
	for _, dir := range s.Layouts {
		if err := visit(dir, func() error { return r.layout(ctx, dir, dir) }); err != nil {
			return err
		}
	}
	if s.Logger != nil {
		s.Logger.Info("container scan coverage", "images", r.images, "layers", r.layers, "files_enumerated", r.files)
	}
	return ctx.Err()
}

type imageStore struct {
	manifest func(v1.Descriptor) ([]byte, error)
	blob     func(v1.Descriptor) (io.ReadCloser, error)
}

func (r *session) registry(ctx context.Context, target string) error {
	opts := []name.Option{}
	if r.s.PlainHTTP {
		opts = append(opts, name.Insecure)
	}
	ref, err := name.ParseReference(target, opts...)
	if err != nil {
		return fmt.Errorf("invalid registry reference: %w", err)
	}
	ro := []remote.Option{remote.WithContext(ctx)}
	if r.s.Anonymous {
		ro = append(ro, remote.WithAuth(authn.Anonymous))
	} else {
		keychain := r.s.Keychain
		if keychain == nil {
			keychain = registryKeychain{allowHelpers: r.s.CredentialHelpers}
		}
		ro = append(ro, remote.WithAuthFromKeychain(keychain))
	}
	if r.s.Transport != nil {
		ro = append(ro, remote.WithTransport(r.s.Transport))
	}
	resolve := r.startProgress(ctx, "container image resolution", "image", ref.Name(), "anonymous", r.s.Anonymous)
	desc, err := remote.Get(ref, ro...)
	resolve.finish(err)
	if err != nil {
		return err
	}
	r.debug(ctx, "resolved container image", "image", ref.Name(), "digest", desc.Digest.String(), "media_type", desc.MediaType)
	store := imageStore{
		manifest: func(d v1.Descriptor) ([]byte, error) {
			if d.Data != nil {
				return d.Data, nil
			}
			fetch := r.startProgress(ctx, "container manifest fetch", "image", ref.Name(), "digest", d.Digest.String())
			v, err := remote.Get(ref.Context().Digest(d.Digest.String()), ro...)
			fetch.finish(err)
			if err != nil {
				return nil, err
			}
			return v.Manifest, nil
		},
		blob: func(d v1.Descriptor) (io.ReadCloser, error) {
			if d.Data != nil {
				return io.NopCloser(bytes.NewReader(d.Data)), nil
			}
			v, err := remote.Layer(ref.Context().Digest(d.Digest.String()), ro...)
			if err != nil {
				return nil, err
			}
			return v.Compressed()
		},
	}
	return r.walk(ctx, store, desc.Manifest, desc.Descriptor, map[string]string{AttrImage: ref.Name()}, 0)
}

const maxMetadataSize = 64 << 20
const maxManifestVisits = 10_000

var errManifestVisits = errors.New("container target exceeds 10000 manifest visits")

func (r *session) walk(ctx context.Context, store imageStore, raw []byte, desc v1.Descriptor, attrs map[string]string, depth int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth == 0 {
		// The root is already loaded. Children are charged before fetching so
		// missing manifests consume the same budget as successfully read ones.
		r.manifestVisits = 1
	}
	if depth > 32 {
		return errors.New("image index nesting exceeds 32")
	}
	if len(raw) > maxMetadataSize {
		return fmt.Errorf("manifest exceeds %d MiB metadata limit", maxMetadataSize>>20)
	}
	if int64(len(raw)) != desc.Size {
		return errors.New("manifest size does not match descriptor")
	}
	if desc.Digest.Hex == "" {
		return errors.New("missing manifest digest")
	}
	if err := checkDigest(raw, desc.Digest); err != nil {
		return err
	}
	attrs = maps.Clone(attrs)
	attrs[AttrDigest] = desc.Digest.String()
	var envelope struct {
		SchemaVersion int             `json:"schemaVersion"`
		Manifests     json.RawMessage `json:"manifests"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return err
	}
	if envelope.SchemaVersion != 2 {
		return errors.New("unsupported image schema (expected Docker schema 2 or OCI)")
	}
	if envelope.Manifests != nil {
		attrs[AttrIndexDigest] = desc.Digest.String()
		if err := r.metadata(ctx, raw, "@index", ResourceIndex, attrs); err != nil {
			return err
		}
		var index v1.IndexManifest
		if err := json.Unmarshal(raw, &index); err != nil {
			return err
		}
		if len(index.Manifests) == 0 {
			return errors.New("image index has no manifests")
		}
		r.debug(ctx, "enumerating container index", "image", attrs[AttrImage], "digest", desc.Digest.String(), "manifests", len(index.Manifests))
		for _, child := range index.Manifests {
			if err := ctx.Err(); err != nil {
				return err
			}
			if child.Platform != nil && !r.matches(child.Platform) {
				r.debug(ctx, "skipping container platform", "image", attrs[AttrImage], "platform", child.Platform.String(), "digest", child.Digest.String())
				continue
			}
			// Count repeated references and failures, not just parsed manifests.
			if r.manifestVisits >= maxManifestVisits {
				return errManifestVisits
			}
			r.manifestVisits++
			childAttrs := maps.Clone(attrs)
			if child.Platform != nil {
				childAttrs[AttrPlatform] = child.Platform.String()
			}
			r.debug(ctx, "selected container manifest", "image", attrs[AttrImage], "platform", childAttrs[AttrPlatform], "digest", child.Digest.String())
			data, err := store.manifest(child)
			if err == nil {
				err = r.walk(ctx, store, data, child, childAttrs, depth+1)
			}
			if err != nil {
				if r.stopped != nil {
					return r.stopped
				}
				if errors.Is(err, errManifestVisits) {
					return err // Stop this target, not just this repeated branch.
				}
				if err := r.yield(sources.Fragment{}, fmt.Errorf("manifest %s: %w", child.Digest, err)); err != nil {
					return err
				}
			}
		}
		// A branch with no selected platforms is an ordinary exclusion. The
		// target-level check in Fragments decides whether anything matched.
		return ctx.Err()
	}
	var manifest v1.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	configProgress := r.startProgress(ctx, "container config read", "image", attrs[AttrImage], "digest", manifest.Config.Digest.String())
	config, err := readBlob(ctx, store, manifest.Config, maxMetadataSize)
	configProgress.finish(err)
	attrs[AttrConfigDigest] = manifest.Config.Digest.String()
	var cfg v1.ConfigFile
	if err == nil {
		err = json.Unmarshal(config, &cfg)
	}
	configValid := err == nil
	if err != nil {
		if err := r.yield(sources.Fragment{}, fmt.Errorf("image %s config: %w", desc.Digest, err)); err != nil {
			return err
		}
		// The manifest still identifies independently scannable layers. A
		// missing config must not suppress their content or manifest annotations.
		config, cfg = []byte("{}"), v1.ConfigFile{}
	}
	if cfg.OS != "" && cfg.Architecture != "" {
		p := &v1.Platform{OS: cfg.OS, Architecture: cfg.Architecture, Variant: cfg.Variant}
		if !r.matches(p) {
			r.debug(ctx, "skipping container platform", "image", attrs[AttrImage], "platform", p.String(), "digest", desc.Digest.String())
			return nil
		}
		attrs[AttrPlatform] = p.String()
		if cfg.OS != "unknown" {
			r.selectedPlatforms++
		}
	}
	r.images++
	imageAttribution(attrs, cfg, manifest.Annotations)
	if err := r.metadata(ctx, raw, "@manifest", ResourceManifest, attrs); err != nil {
		return err
	}
	layers := make([]layerInput, len(manifest.Layers))
	for i, d := range manifest.Layers {
		layers[i] = layerInput{descriptor: d, open: func() (io.ReadCloser, error) {
			if d.Digest.Hex == "" {
				return nil, errors.New("missing layer digest")
			}
			return store.blob(d)
		}}
		if i < len(cfg.RootFS.DiffIDs) {
			layers[i].diffID = cfg.RootFS.DiffIDs[i]
		}
	}
	if configValid && manifest.Config.MediaType.IsConfig() && len(cfg.RootFS.DiffIDs) != len(layers) {
		if err := r.yield(sources.Fragment{}, errors.New("layer count does not match config rootfs diff_ids")); err != nil {
			return err
		}
	}
	return r.image(ctx, config, cfg, layers, attrs)
}

func (r *session) matches(p *v1.Platform) bool {
	// Attestations commonly use unknown/unknown. Always inspect these, including
	// when filtering runtime platforms: build metadata can itself leak secrets.
	if len(r.s.Platforms) == 0 || p.OS == "unknown" || p.OS == "" {
		return true
	}
	for _, filter := range r.s.Platforms {
		parts := strings.Split(filter, "/")
		if p.OS == parts[0] && p.Architecture == parts[1] && (len(parts) == 2 || p.Variant == parts[2]) {
			return true
		}
	}
	return false
}

func (r *session) image(ctx context.Context, raw []byte, cfg v1.ConfigFile, layers []layerInput, attrs map[string]string) error {
	r.debug(ctx, "scanning container image", "image", attrs[AttrImage], "digest", attrs[AttrDigest], "platform", attrs[AttrPlatform], "layers", len(layers), "history_entries", len(cfg.History))
	r.debug(ctx, "scanning container metadata", "image", attrs[AttrImage], "platform", attrs[AttrPlatform])
	var config map[string]json.RawMessage
	if err := json.Unmarshal(raw, &config); err != nil {
		return err
	}
	delete(config, "history")
	configRaw, err := json.Marshal(config)
	if err != nil {
		return err
	}
	if err := r.metadata(ctx, configRaw, "@config", ResourceConfig, attrs); err != nil {
		return err
	}
	var history []json.RawMessage
	var original struct {
		History []json.RawMessage `json:"history"`
	}
	if err := json.Unmarshal(raw, &original); err != nil {
		return err
	}
	history = original.History
	li := 0
	for i, h := range history {
		a := maps.Clone(attrs)
		a[AttrHistoryIndex] = strconv.Itoa(i)
		if i < len(cfg.History) && !cfg.History[i].EmptyLayer {
			if li < len(layers) {
				layerAttributes(a, layers[li], li)
			}
			li++
		}
		if err := r.metadata(ctx, h, fmt.Sprintf("@history/%d", i), ResourceHistory, a); err != nil {
			return err
		}
	}
	state := newOverlay()
	// Windows layers are still scanned, but POSIX whiteouts do not describe all
	// Windows filesystem semantics (including case folding and tombstones).
	state.unknown = strings.HasPrefix(attrs[AttrPlatform], "windows/")
	for i := len(layers) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return err
		}
		a := maps.Clone(attrs)
		layerAttributes(a, layers[i], i)
		r.debug(ctx, "scanning container layer", "image", attrs[AttrImage], "platform", attrs[AttrPlatform], "layer_index", i, "layer_count", len(layers))
		if err := r.layer(ctx, layers[i], a, state); err != nil {
			if r.stopped != nil {
				return r.stopped
			}
			state.unknown = true
			if err := r.yield(sources.Fragment{}, fmt.Errorf("layer %d: %w", i, err)); err != nil {
				return err
			}
		} else {
			r.layers++
		}
	}
	return ctx.Err()
}

// Image labels and annotations are declarations, not verified authorship.
// Prefer config labels to manifest annotations; keep authors freeform as OCI
// specifies instead of guessing a single person's name and email address.
func imageAttribution(attrs map[string]string, cfg v1.ConfigFile, annotations map[string]string) {
	for _, field := range []struct{ attr, key string }{
		{AttrAuthors, "org.opencontainers.image.authors"},
		{AttrSourceURL, "org.opencontainers.image.source"},
		{AttrRevision, "org.opencontainers.image.revision"},
	} {
		value := strings.TrimSpace(cfg.Config.Labels[field.key])
		if value == "" {
			value = strings.TrimSpace(annotations[field.key])
		}
		if value == "" && field.attr == AttrAuthors {
			value = strings.TrimSpace(cfg.Config.Labels["maintainer"])
			if value == "" {
				value = strings.TrimSpace(cfg.Author)
			}
		}
		// Do not multiply an arbitrarily large label into every file finding.
		// Its full content is still scanned in the original metadata.
		if value != "" && len(value) <= 4096 {
			attrs[field.attr] = value
		}
	}
}

func layerAttributes(a map[string]string, l layerInput, i int) {
	a[AttrLayerIndex] = strconv.Itoa(i)
	a[AttrMediaType] = string(l.descriptor.MediaType)
	if l.descriptor.Digest.Hex != "" {
		a[AttrLayerDigest] = l.descriptor.Digest.String()
	}
	if l.diffID.Hex != "" {
		a[AttrDiffID] = l.diffID.String()
	}
}
