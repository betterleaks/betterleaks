package container

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"strconv"
	"strings"

	"github.com/betterleaks/betterleaks/sources"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/rs/zerolog"
)

type layerInput struct {
	descriptor v1.Descriptor
	diffID     v1.Hash
	open       func() (io.ReadCloser, error)
}

func (r *session) layer(ctx context.Context, l layerInput, attrs map[string]string, state *overlay) (err error) {
	logger := zerolog.Nop()
	if r.s.Logger != nil {
		logger = r.s.Logger.With().Str("image", attrs[AttrImage]).Str("platform", attrs[AttrPlatform]).Str("layer_index", attrs[AttrLayerIndex]).Str("layer_digest", attrs[AttrLayerDigest]).Str("diff_id", attrs[AttrDiffID]).Logger()
	}
	progress := r.startProgress(ctx, "container layer scan", "image", attrs[AttrImage], "platform", attrs[AttrPlatform], "layer_index", attrs[AttrLayerIndex], "layer_digest", attrs[AttrLayerDigest], "diff_id", attrs[AttrDiffID], "blob_size", l.descriptor.Size)
	defer func() { progress.finish(err) }()
	progress.setPhase("opening")
	reader, err := l.open()
	if err != nil {
		return err
	}
	defer reader.Close()
	progress.setPhase("reading and scanning")
	compressed := progress.reader(contextReader{ctx, reader})
	if l.descriptor.Digest.Hex != "" {
		// Docker save layers have a diff ID but no stored-blob descriptor.
		compressed, err = descriptorReader(compressed, l.descriptor)
	}
	if err != nil {
		return err
	}
	if strings.HasSuffix(string(l.descriptor.MediaType), "+encrypted") {
		return errors.New("encrypted container layer cannot be scanned")
	}
	isLayer := l.descriptor.MediaType.IsLayer() || l.descriptor.MediaType == "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd"
	if !isLayer {
		// OCI attestations, provenance, and SBOM payloads are blobs, not tar.
		a := maps.Clone(attrs)
		a[sources.AttrResource] = ResourceArtifact
		location := "@artifact/" + l.descriptor.Digest.String()
		a[sources.AttrPath] = location
		if r.s.Prefilter != nil && r.s.Prefilter(a) {
			_, err := io.Copy(io.Discard, compressed)
			return err
		}
		if r.s.MaxFileSize > 0 && l.descriptor.Size > r.s.MaxFileSize {
			return errors.New("artifact exceeds --max-file-size")
		}
		if strings.HasSuffix(string(l.descriptor.MediaType), "+json") || l.descriptor.MediaType == "application/json" {
			data, err := io.ReadAll(io.LimitReader(compressed, maxMetadataSize+1))
			if err != nil {
				return err
			}
			if len(data) > maxMetadataSize {
				return errors.New("JSON artifact exceeds 16 MiB metadata limit")
			}
			return r.metadata(ctx, data, location, ResourceArtifact, a)
		}
		file := sources.File{
			Content:         compressed,
			Path:            location,
			Attributes:      a,
			Logger:          &logger,
			ShouldSkip:      r.s.Prefilter,
			DetectArchive:   true,
			StrictArchives:  true,
			ScanBinary:      true,
			MaxArchiveDepth: r.s.MaxArchiveDepth,
		}
		if err := file.Fragments(ctx, r.yield); err != nil {
			return err
		}
		_, err = io.Copy(io.Discard, compressed)
		return err
	}
	content, err := decompress(compressed)
	if err != nil {
		return err
	}
	defer content.Close()
	uncompressed, err := verifyingReader(content, l.diffID)
	if err != nil {
		return err
	}
	t := tar.NewReader(uncompressed)
	pending := newOverlay()
	order, _ := strconv.Atoi(attrs[AttrLayerIndex])
	seen := map[string]bool{}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		h, err := t.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		p, err := layerPath(h.Name)
		if err != nil {
			return err
		}
		if err := state.budget.add(p); err != nil {
			return err
		}
		if seen[p] {
			return fmt.Errorf("duplicate layer entry %q", p)
		}
		seen[p] = true
		a := maps.Clone(attrs)
		a[AttrPathState], a[AttrHiddenByLayer] = state.lookup(p)
		if a[AttrHiddenByLayer] == "" {
			delete(a, AttrHiddenByLayer)
		}
		id := attrs[AttrLayerDigest]
		if id == "" {
			id = attrs[AttrDiffID]
		}
		base := path.Base(p)
		if strings.HasPrefix(base, ".wh.") && (base == ".wh." || h.Size != 0 || (h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA)) {
			return fmt.Errorf("invalid OCI whiteout %q", p)
		}
		if base == ".wh..wh..opq" {
			pending.opaque[path.Dir(p)] = change{"deleted", id, order}
		} else if strings.HasPrefix(base, ".wh.") {
			target := path.Join(path.Dir(p), strings.TrimPrefix(base, ".wh."))
			// Whiteouts remove lower occurrences before same-layer additions.
			pending.trees[target] = change{"deleted", id, order}
		} else if h.Typeflag == tar.TypeDir && p != "/" {
			pending.exact[p] = change{"overwritten", id, order}
		} else if h.Typeflag != tar.TypeDir && pending.trees[p].state != "deleted" {
			pending.trees[p] = change{"overwritten", id, order}
		}
		// Header values can carry secrets even on links and special files. Never
		// follow links or create a container filesystem on the host.
		header := map[string]any{"name": h.Name}
		if h.Linkname != "" {
			header["linkname"] = h.Linkname
		}
		if h.Uname != "" {
			header["uname"] = h.Uname
		}
		if h.Gname != "" {
			header["gname"] = h.Gname
		}
		if len(h.PAXRecords) > 0 {
			header["pax"] = h.PAXRecords
		}
		raw, _ := json.Marshal(header)
		if err := r.metadata(ctx, raw, p, ResourceLayerMetadata, a); err != nil {
			return err
		}
		if strings.HasPrefix(base, ".wh.") {
			continue
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA && h.Typeflag != tar.TypeGNUSparse {
			continue
		}
		r.files++
		progress.file()
		a[sources.AttrResource], a[sources.AttrPath] = ResourceFile, p
		if r.s.Prefilter != nil && r.s.Prefilter(a) {
			continue
		}
		if r.s.MaxFileSize > 0 && h.Size > r.s.MaxFileSize {
			if err := r.yield(sources.Fragment{}, fmt.Errorf("file %q exceeds --max-file-size", p)); err != nil {
				return err
			}
			continue
		}
		file := sources.File{
			Content:         t,
			Path:            p,
			Attributes:      a,
			Logger:          &logger,
			ShouldSkip:      r.s.Prefilter,
			MaxArchiveDepth: r.s.MaxArchiveDepth,
			DetectArchive:   true,
			StrictArchives:  true,
			ScanBinary:      true,
		}
		if err := file.Fragments(ctx, r.yield); err != nil {
			return err
		}
	}
	// tar EOF occurs before the end of the blob. Drain padding and compression
	// trailers to check both content digests and detect truncated downloads.
	progress.setPhase("verifying trailers")
	if err := drainLayerTail(ctx, uncompressed); err != nil {
		return err
	}
	if _, err := io.Copy(io.Discard, compressed); err != nil {
		return err
	}
	state.merge(pending)
	return nil
}

func layerPath(name string) (string, error) {
	// Interpret names using container (POSIX) semantics on every host OS.
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", fmt.Errorf("unsafe layer path %q", name)
		}
	}
	if strings.ContainsRune(name, 0) {
		return "", errors.New("NUL in layer path")
	}
	return path.Clean("/" + name), nil
}

type change struct {
	state, layer string
	order        int
}
type overlay struct {
	exact, trees, opaque map[string]change
	unknown              bool
	budget               layerEntryBudget
}

const (
	maxImageLayerEntries = 1_000_000
	maxImagePathBytes    = 64 << 20
)

// This budget spans every layer of one image, including excluded entries.
// An entry-count limit alone does not bound memory when names are very long.
type layerEntryBudget struct {
	entries   int
	pathBytes int
}

func (b *layerEntryBudget) add(p string) error {
	if b.entries >= maxImageLayerEntries {
		return errors.New("image layers exceed one million entries")
	}
	if len(p) > maxImagePathBytes-b.pathBytes {
		return errors.New("image layer paths exceed 64 MiB")
	}
	b.entries++
	b.pathBytes += len(p)
	return nil
}

func newOverlay() *overlay {
	return &overlay{exact: map[string]change{}, trees: map[string]change{}, opaque: map[string]change{}}
}
func (o *overlay) lookup(p string) (string, string) {
	if o.unknown {
		return "unknown", ""
	}
	first := change{state: "visible", order: -1}
	consider := func(c change) {
		if c.state != "" && (first.order == -1 || c.order < first.order || (c.order == first.order && c.state == "deleted")) {
			first = c
		}
	}
	consider(o.exact[p])
	for current := p; ; current = path.Dir(current) {
		consider(o.trees[current])
		if current != p {
			consider(o.opaque[current])
		}
		if current == "/" {
			break
		}
	}
	return first.state, first.layer
}
func (o *overlay) merge(n *overlay) {
	// Walking backwards, each newly visited change is closer to the remaining
	// older occurrences. Retain their first hiding event, not the final occupant.
	maps.Copy(o.exact, n.exact)
	maps.Copy(o.trees, n.trees)
	maps.Copy(o.opaque, n.opaque)
}
