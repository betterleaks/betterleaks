package container

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/betterleaks/betterleaks/v2/sources"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func (r *session) archive(ctx context.Context, file string) error {
	r.debug(ctx, "opening container archive", "archive", file)
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	return r.unpack(ctx, f, file)
}

func (r *session) daemon(ctx context.Context, ref string) error {
	r.debug(ctx, "exporting container image from Docker daemon", "image", ref)
	// Use Docker's configured context and credential/socket handling. Export
	// exactly the requested local image; there is no registry fallback.
	cmd := exec.CommandContext(ctx, "docker", "image", "save", "--", ref)
	stderr := &daemonDiagnostic{}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start docker image save: %w", err)
	}
	err = r.unpack(ctx, stdout, "daemon:"+ref)
	if err != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if waitErr != nil {
		// Preserve the producer's explanation instead of replacing it with
		// the secondary missing/truncated-archive error. The session sanitizes
		// URLs in all yielded diagnostics before handing them to the scanner.
		return errors.Join(fmt.Errorf("docker image save failed: %w: %s", waitErr, stderr.String()), err)
	}
	return err
}

// Docker can emit arbitrary amounts of stderr. Keep a bounded diagnostic while
// accepting every write so its stderr pipe cannot block the export process.
type daemonDiagnostic struct {
	buffer    bytes.Buffer
	truncated bool
}

func (d *daemonDiagnostic) Write(p []byte) (int, error) {
	n := len(p)
	keep := min(n, (16<<10)-d.buffer.Len())
	_, _ = d.buffer.Write(p[:keep])
	d.truncated = d.truncated || keep != n
	return n, nil
}

func (d *daemonDiagnostic) String() string {
	message := strings.TrimSpace(d.buffer.String())
	if d.truncated {
		message += " [truncated]"
	}
	return message
}

func (r *session) unpack(ctx context.Context, input io.Reader, target string) error {
	dir, err := os.MkdirTemp("", "betterleaks-container-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := r.unpackFiles(ctx, input, root, target); err != nil {
		return err
	}
	if _, err := root.Stat("index.json"); err == nil {
		return r.layout(ctx, dir, target)
	}
	return r.dockerArchive(ctx, root, target)
}

func (r *session) unpackFiles(ctx context.Context, input io.Reader, root *os.Root, target string) (err error) {
	progress := r.startProgress(ctx, "container archive extraction", "image", target)
	defer func() { progress.finish(err) }()
	stream, err := decompress(progress.reader(contextReader{ctx, input}))
	if err != nil {
		return err
	}
	defer stream.Close()
	limit := r.s.MaxArchiveSize
	if limit == 0 {
		limit = 20 << 30
	}
	expanded := &budgetReader{
		reader:    contextReader{ctx, stream},
		remaining: limit,
		limitErr:  errors.New("expanded image archive exceeds --max-archive-size"),
	}
	t := tar.NewReader(expanded)
	// Also bound logical file sizes: sparse tar members can write more bytes
	// than the decompressed tar stream contains.
	var used int64
	entries := 0
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
		entries++
		if entries > 1_000_000 {
			return errors.New("image archive exceeds one million entries")
		}
		p, err := archivePath(h.Name)
		if err != nil {
			return err
		}
		if h.Typeflag == tar.TypeDir {
			if err := root.MkdirAll(p, 0700); err != nil {
				return err
			}
			continue
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			return fmt.Errorf("unsupported outer archive entry type for %q (links are not followed)", p)
		}
		if h.Size < 0 || h.Size > limit-used {
			return errors.New("expanded image archive exceeds --max-archive-size")
		}
		used += h.Size
		progress.file()
		if err := root.MkdirAll(path.Dir(p), 0700); err != nil {
			return err
		}
		f, err := root.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(f, contextReader{ctx, t})
		closeErr := f.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			return err
		}
	}
	// Consume compression trailers, rejecting truncated compressed archives.
	if _, err := io.Copy(io.Discard, expanded); err != nil {
		return err
	}
	return nil
}

func archivePath(p string) (string, error) {
	if strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || strings.Contains(p, ":") || strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("unsafe image archive path %q", p)
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return "", fmt.Errorf("unsafe image archive path %q", p)
		}
	}
	return path.Clean(p), nil
}

func localRead(ctx context.Context, root *os.Root, p string) ([]byte, error) {
	p, err := archivePath(p)
	if err != nil {
		return nil, err
	}
	f, err := root.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("metadata %q is not a regular file", p)
	}
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx, f}, maxMetadataSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxMetadataSize {
		return nil, errors.New("metadata exceeds 16 MiB limit")
	}
	return data, nil
}

func (r *session) layout(ctx context.Context, dir, target string) error {
	r.debug(ctx, "opening OCI image layout", "image", target)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	marker, err := localRead(ctx, root, "oci-layout")
	if err != nil {
		return fmt.Errorf("read oci-layout: %w", err)
	}
	var version struct {
		Version string `json:"imageLayoutVersion"`
	}
	if err := json.Unmarshal(marker, &version); err != nil {
		return err
	}
	if version.Version != "1.0.0" {
		return fmt.Errorf("unsupported OCI layout version %q", version.Version)
	}
	store := imageStore{}
	store.blob = func(d v1.Descriptor) (io.ReadCloser, error) {
		if d.Data != nil {
			return io.NopCloser(bytes.NewReader(d.Data)), nil
		}
		if d.Digest.Hex == "" {
			return nil, errors.New("missing OCI blob digest")
		}
		if _, err := verifyingReader(strings.NewReader(""), d.Digest); err != nil {
			return nil, err
		}
		f, err := root.Open(path.Join("blobs", d.Digest.Algorithm, d.Digest.Hex))
		if err != nil {
			return nil, err
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			f.Close()
			return nil, errors.New("OCI blob is not a regular file")
		}
		return f, nil
	}
	store.manifest = func(d v1.Descriptor) ([]byte, error) { return readBlob(ctx, store, d, maxMetadataSize) }
	index, err := localRead(ctx, root, "index.json")
	if err != nil {
		return err
	}
	return r.walk(ctx, store, index, v1.Descriptor{Digest: sum(index), Size: int64(len(index)), MediaType: types.OCIImageIndex}, map[string]string{AttrImage: target}, 0)
}

func sum(data []byte) v1.Hash {
	h := sha256.Sum256(data)
	return v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(h[:])}
}

func (r *session) dockerArchive(ctx context.Context, root *os.Root, target string) error {
	raw, err := localRead(ctx, root, "manifest.json")
	if err != nil {
		return fmt.Errorf("expected Docker save manifest.json or OCI index.json: %w", err)
	}
	var manifest []struct {
		Config   string
		RepoTags []string
		Layers   []string
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	if len(manifest) == 0 {
		return errors.New("empty Docker archive manifest")
	}
	if err := r.metadata(ctx, raw, "@archive-manifest", ResourceManifest, map[string]string{AttrImage: target}); err != nil {
		return err
	}
	matched := false
	for _, entry := range manifest {
		if err := ctx.Err(); err != nil {
			return err
		}
		load := func() error {
			config, err := localRead(ctx, root, entry.Config)
			var cfg v1.ConfigFile
			if err == nil {
				err = json.Unmarshal(config, &cfg)
			}
			configValid := err == nil
			if err != nil {
				if err := r.yield(sources.Fragment{}, fmt.Errorf("Docker archive config %q: %w", entry.Config, err)); err != nil {
					return err
				}
				config, cfg = []byte("{}"), v1.ConfigFile{}
			}
			p := &v1.Platform{OS: cfg.OS, Architecture: cfg.Architecture, Variant: cfg.Variant}
			if !r.matches(p) {
				return nil
			}
			matched = true
			if cfg.OS != "" && cfg.OS != "unknown" && cfg.Architecture != "" {
				r.selectedPlatforms++
			}
			if configValid && len(cfg.RootFS.DiffIDs) != len(entry.Layers) {
				if err := r.yield(sources.Fragment{}, errors.New("Docker archive layers do not match config rootfs diff_ids")); err != nil {
					return err
				}
			}
			attrs := map[string]string{AttrImage: target}
			if configValid {
				attrs[AttrConfigDigest], attrs[AttrPlatform] = sum(config).String(), p.String()
			}
			// Docker save does not preserve the registry manifest digest. Never
			// report a synthesized digest as though it identified a registry image.
			if len(entry.RepoTags) > 0 {
				tags, _ := json.Marshal(entry.RepoTags)
				attrs["container.tags"] = string(tags)
			}
			layers := make([]layerInput, len(entry.Layers))
			for i, p := range entry.Layers {
				p, err := archivePath(p)
				if err != nil {
					return err
				}
				layers[i] = layerInput{descriptor: v1.Descriptor{MediaType: types.OCIUncompressedLayer}, open: func() (io.ReadCloser, error) { return root.Open(p) }}
				if i < len(cfg.RootFS.DiffIDs) {
					layers[i].diffID = cfg.RootFS.DiffIDs[i]
				}
			}
			r.images++
			return r.image(ctx, config, cfg, layers, attrs)
		}
		if err := load(); err != nil {
			if r.stopped != nil {
				return r.stopped
			}
			if err := r.yield(sources.Fragment{}, fmt.Errorf("Docker archive image %q: %w", entry.Config, err)); err != nil {
				return err
			}
		}
	}
	if !matched {
		return errors.New("no images match requested platforms")
	}
	return ctx.Err()
}
