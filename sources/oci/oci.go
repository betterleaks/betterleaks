// Package oci scans local OCI image layouts without unpacking a root filesystem.
package oci

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"maps"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/filesystem"
	"github.com/dustin/go-humanize"
	"github.com/klauspost/compress/zstd"
	"github.com/mholt/archives"
	"golang.org/x/sync/errgroup"
)

const (
	AttrLayout     = "oci.layout"
	AttrDigest     = "oci.digest"
	AttrFilePath   = "oci.file_path"
	ResourceLayer  = "oci.layer_content"
	ResourceConfig = "oci.config"
	// maxMetadataSize bounds layout, index, manifest, and config documents.
	maxMetadataSize = 16 << 20
	// DefaultMaxLayerSize bounds decoded layer streams and individual layer files,
	// including logical sizes reconstructed for GNU sparse entries.
	DefaultMaxLayerSize int64 = 4 << 30
	maxIndexDepth             = 32
	imageIndex                = "application/vnd.oci.image.index.v1+json"
	imageManifest             = "application/vnd.oci.image.manifest.v1+json"
	imageConfig               = "application/vnd.oci.image.config.v1+json"
	dockerIndex               = "application/vnd.docker.distribution.manifest.list.v2+json"
	dockerManifest            = "application/vnd.docker.distribution.manifest.v2+json"
	dockerConfig              = "application/vnd.docker.container.image.v1+json"
	layerTar                  = "application/vnd.oci.image.layer.v1.tar"
)

// Layout scans every referenced image by default, including files hidden by
// later layers. Ref selects a top-level org.opencontainers.image.ref.name;
// Platform selects os/architecture[/variant]. Shared blobs are scanned once.
// The image envelope does not count towards MaxArchiveDepth, which applies to
// archives inside layer files. Nested archives use filesystem.File's skip policy.
// Missing, corrupt, unsupported or digest-mismatched image blobs are errors.
// No registry requests are made, and no image entries are extracted to disk.
type Layout struct {
	Path            string
	Ref             string
	Platform        string
	Logger          *slog.Logger
	Prefilter       sources.PrefilterFunc
	MaxArchiveDepth int
	// MaxLayerSize limits decompressed bytes per layer and logical file sizes.
	// Zero uses DefaultMaxLayerSize.
	MaxLayerSize int64
}

type platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant"`
}

func (p platform) String() string {
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations"`
	Platform    *platform         `json:"platform"`
}
type manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	Manifests     []descriptor `json:"manifests"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
}
type task struct {
	desc        descriptor
	config      bool
	configBytes []byte
}

type traversal struct {
	source  *Layout
	root    *os.Root
	visited map[string]descriptor
	tasks   map[string]task
	ordered []task
	images  int
}

func (s *Layout) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.MaxArchiveDepth < 0 {
		return errors.New("OCI MaxArchiveDepth must not be negative")
	}
	if s.MaxLayerSize < 0 {
		return errors.New("OCI MaxLayerSize must not be negative")
	}
	if s.Platform != "" {
		parts := strings.Split(s.Platform, "/")
		if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" || (len(parts) == 3 && parts[2] == "") {
			return errors.New("OCI platform must be os/architecture[/variant]")
		}
	}
	root, err := os.OpenRoot(s.Path)
	if err != nil {
		return fmt.Errorf("open OCI layout: %w", err)
	}
	defer root.Close()
	b, err := readSmall(root, "oci-layout")
	if err != nil {
		return err
	}
	var version struct {
		Version string `json:"imageLayoutVersion"`
	}
	if err = json.Unmarshal(b, &version); err != nil {
		return fmt.Errorf("decode oci-layout: %w", err)
	}
	if version.Version != "1.0.0" {
		return fmt.Errorf("unsupported OCI layout version %q", version.Version)
	}
	b, err = readSmall(root, "index.json")
	if err != nil {
		return err
	}
	var index manifest
	if err = json.Unmarshal(b, &index); err != nil {
		return fmt.Errorf("decode OCI index: %w", err)
	}
	if index.SchemaVersion != 2 {
		return errors.New("OCI index requires schemaVersion 2")
	}
	t := &traversal{source: s, root: root, visited: map[string]descriptor{}, tasks: map[string]task{}}
	for _, desc := range index.Manifests {
		if s.Ref != "" && desc.Annotations["org.opencontainers.image.ref.name"] != s.Ref {
			continue
		}
		if err = t.visit(ctx, desc, 0); err != nil {
			return err
		}
	}
	if t.images == 0 {
		return errors.New("no OCI images match the requested ref/platform")
	}
	group, workCtx := errgroup.WithContext(ctx)
	group.SetLimit(min(runtime.GOMAXPROCS(0), 4))
	for _, job := range t.ordered {
		if err := workCtx.Err(); err != nil {
			break
		}
		group.Go(func() error { return t.scan(workCtx, job, yield) })
	}
	if err := group.Wait(); err != nil {
		return err
	}
	return ctx.Err()
}

func (t *traversal) visit(ctx context.Context, d descriptor, depth int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth > maxIndexDepth {
		return errors.New("OCI index nesting exceeds limit")
	}
	// BuildKit provenance/attestation manifests are not filesystem images.
	if d.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
		return nil
	}
	// This is a pre-filter only: a missing variant here may still be present
	// in the image config, so it rejects a definite mismatch, not an absence.
	if d.Platform != nil && t.source.Platform != "" && !couldMatch(*d.Platform, t.source.Platform) {
		return nil
	}
	if prior, ok := t.visited[d.Digest]; ok {
		if prior.Size != d.Size || prior.MediaType != d.MediaType {
			return fmt.Errorf("conflicting OCI manifest descriptors for %s", d.Digest)
		}
		return nil
	}
	t.visited[d.Digest] = d
	b, err := metadata(ctx, t.root, d)
	if err != nil {
		return err
	}
	var m manifest
	if err = json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("decode OCI manifest %s: %w", d.Digest, err)
	}
	if m.SchemaVersion != 2 {
		return fmt.Errorf("manifest %s requires schemaVersion 2", d.Digest)
	}
	switch d.MediaType {
	case imageIndex, dockerIndex:
		for _, child := range m.Manifests {
			if err := t.visit(ctx, child, depth+1); err != nil {
				return err
			}
		}
	case imageManifest, dockerManifest:
		if m.Config.MediaType != imageConfig && m.Config.MediaType != dockerConfig {
			return fmt.Errorf("unsupported OCI config type %q", m.Config.MediaType)
		}
		config, err := metadata(ctx, t.root, m.Config)
		if err != nil {
			return err
		}
		var p platform
		if err := json.Unmarshal(config, &p); err != nil {
			return fmt.Errorf("decode OCI config: %w", err)
		}
		if p.OS == "" || p.Architecture == "" {
			return errors.New("OCI image config requires os and architecture")
		}
		// Some producers include the optional CPU variant only in the index.
		if p.Variant == "" && d.Platform != nil {
			p.Variant = d.Platform.Variant
		}
		if t.source.Platform != "" && !matches(p, t.source.Platform) {
			return nil
		}
		t.images++
		if err := t.add(task{desc: m.Config, config: true, configBytes: config}); err != nil {
			return err
		}
		for _, layer := range m.Layers {
			if _, err := compression(layer.MediaType); err != nil {
				return err
			}
			if err := t.add(task{desc: layer}); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported OCI manifest type %q", d.MediaType)
	}
	return nil
}
func matches(p platform, selection string) bool {
	return p.String() == selection || (strings.Count(selection, "/") == 1 && p.OS+"/"+p.Architecture == selection)
}

// couldMatch reports whether p could still satisfy selection once any
// variant missing from p is later filled in from another source (e.g. the
// index descriptor is missing a variant recorded only in the image config).
func couldMatch(p platform, selection string) bool {
	parts := strings.SplitN(selection, "/", 3)
	if p.OS != parts[0] || p.Architecture != parts[1] {
		return false
	}
	return p.Variant == "" || len(parts) < 3 || p.Variant == parts[2]
}
func (t *traversal) add(job task) error {
	if prior, ok := t.tasks[job.desc.Digest]; ok {
		if prior.desc.Size != job.desc.Size || prior.desc.MediaType != job.desc.MediaType || prior.config != job.config {
			return fmt.Errorf("conflicting OCI descriptors for %s", job.desc.Digest)
		}
		return nil
	}
	t.tasks[job.desc.Digest] = job
	t.ordered = append(t.ordered, job)
	return nil
}

func (t *traversal) scan(ctx context.Context, job task, yield sources.FragmentsFunc) error {
	d := job.desc
	attrs := map[string]string{AttrLayout: t.source.Path, AttrDigest: d.Digest, sources.AttrResource: ResourceLayer}
	if job.config {
		attrs[sources.AttrResource] = ResourceConfig
		attrs[sources.AttrPath] = d.Digest + "/config.json"
		r := sources.Reader{Content: bytes.NewReader(job.configBytes), Attributes: attrs, Prefilter: t.source.Prefilter}
		return r.Fragments(ctx, yield)
	}
	return withBlob(ctx, t.root, d, func(raw io.Reader) error {
		encoding, err := compression(d.MediaType)
		if err != nil {
			return err
		}
		content := raw
		switch encoding {
		case "gzip":
			r, err := (archives.Gz{}).OpenReader(raw)
			if err != nil {
				return err
			}
			defer r.Close()
			content = r
		case "zstd":
			r, err := (archives.Zstd{DecoderOptions: []zstd.DOption{zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(256 << 20)}}).OpenReader(raw)
			if err != nil {
				return err
			}
			defer r.Close()
			content = r
		}
		limit := t.source.MaxLayerSize
		if limit == 0 {
			limit = DefaultMaxLayerSize
		}
		content = &boundedReader{reader: content, limit: limit}
		tr := tar.NewReader(content)
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return fmt.Errorf("read OCI layer tar: %w", err)
			}
			if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA && h.Typeflag != tar.TypeGNUSparse {
				continue
			}
			if h.Size > limit {
				return fmt.Errorf("OCI layer file %q exceeds size limit of %s", h.Name, humanize.IBytes(uint64(limit)))
			}
			// Whiteouts are layer operations, not file contents. Never apply them:
			// files from earlier layers must still be scanned.
			name := path.Clean(h.Name)
			if strings.HasPrefix(path.Base(name), ".wh.") {
				continue
			}
			if name == "." || strings.HasPrefix(name, "/") || name == ".." || strings.HasPrefix(name, "../") {
				return fmt.Errorf("invalid OCI layer path %q", h.Name)
			}
			fileAttrs := maps.Clone(attrs)
			fileAttrs[AttrFilePath] = name
			f := filesystem.File{Content: tr, Path: d.Digest + "!" + name, Attributes: fileAttrs, Logger: t.source.Logger, Prefilter: t.source.Prefilter, MaxArchiveDepth: t.source.MaxArchiveDepth}
			if err := f.Fragments(ctx, yield); err != nil {
				return err
			}
		}
		// Read through the compression footer (tar stops before it) to detect
		// truncated streams and checksum failures, including empty layers.
		_, err = io.Copy(io.Discard, contextReader{ctx, content})
		return err
	})
}

func compression(mediaType string) (string, error) {
	switch mediaType {
	case layerTar, "application/vnd.oci.image.layer.nondistributable.v1.tar":
		return "", nil
	case layerTar + "+gzip", "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip", "application/vnd.docker.image.rootfs.diff.tar.gzip", "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip":
		return "gzip", nil
	case layerTar + "+zstd", "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd":
		return "zstd", nil
	default:
		return "", fmt.Errorf("unsupported OCI layer type %q", mediaType)
	}
}

func readSmall(root *os.Root, name string) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open OCI %s: %w", name, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > maxMetadataSize {
		return nil, fmt.Errorf("invalid or oversized OCI metadata %s", name)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxMetadataSize+1))
	if len(b) > maxMetadataSize {
		return nil, fmt.Errorf("OCI metadata %s exceeds size limit", name)
	}
	return b, err
}
func metadata(ctx context.Context, root *os.Root, d descriptor) ([]byte, error) {
	if d.Size > maxMetadataSize {
		return nil, fmt.Errorf("OCI metadata %s exceeds size limit", d.Digest)
	}
	var b []byte
	err := withBlob(ctx, root, d, func(r io.Reader) error { var err error; b, err = io.ReadAll(r); return err })
	return b, err
}
func digestHash(digest string) (hash.Hash, string, error) {
	algorithm, encoded, ok := strings.Cut(digest, ":")
	var h hash.Hash
	switch algorithm {
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	default:
		return nil, "", fmt.Errorf("unsupported OCI digest %q", digest)
	}
	if !ok || len(encoded) != h.Size()*2 || strings.ToLower(encoded) != encoded {
		return nil, "", fmt.Errorf("invalid OCI digest %q", digest)
	}
	if _, err := hex.DecodeString(encoded); err != nil {
		return nil, "", fmt.Errorf("invalid OCI digest %q", digest)
	}
	return h, "blobs/" + algorithm + "/" + encoded, nil
}
func withBlob(ctx context.Context, root *os.Root, d descriptor, consume func(io.Reader) error) error {
	h, name, err := digestHash(d.Digest)
	if err != nil {
		return err
	}
	f, err := root.Open(name)
	if err != nil {
		return fmt.Errorf("open OCI blob %s: %w", d.Digest, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || d.Size < 0 || st.Size() != d.Size {
		return fmt.Errorf("OCI blob %s size mismatch or not a regular file", d.Digest)
	}
	reader := io.TeeReader(contextReader{ctx, io.LimitReader(f, d.Size+1)}, h)
	counted := &countReader{Reader: reader}
	if err = consume(counted); err != nil {
		return fmt.Errorf("scan OCI blob %s: %w", d.Digest, err)
	}
	if _, err = io.Copy(io.Discard, counted); err != nil {
		return err
	}
	if counted.n != d.Size {
		return fmt.Errorf("OCI blob %s size changed while scanning", d.Digest)
	}
	if hex.EncodeToString(h.Sum(nil)) != strings.SplitN(d.Digest, ":", 2)[1] {
		return fmt.Errorf("OCI blob %s digest mismatch", d.Digest)
	}
	return ctx.Err()
}

type countReader struct {
	io.Reader
	n int64
}

// boundedReader permits at most limit bytes and reports an error if the
// underlying stream contains more. The probe after reaching the limit
// distinguishes an exact-length stream from one that expands past the limit.
type boundedReader struct {
	reader io.Reader
	limit  int64
	read   int64
}

func (r *boundedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.read == r.limit {
		var probe [1]byte
		n, err := r.reader.Read(probe[:])
		if n > 0 {
			return 0, fmt.Errorf("OCI layer exceeds size limit of %s", humanize.IBytes(uint64(r.limit)))
		}
		return 0, err
	}
	if remaining := r.limit - r.read; int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := r.reader.Read(p)
	r.read += int64(n)
	return n, err
}

func (r *countReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.n += int64(n)
	return n, err
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
