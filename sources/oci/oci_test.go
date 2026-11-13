package oci

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"
)

type fixture struct {
	t   *testing.T
	dir string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t, t.TempDir()}
	require.NoError(t, os.MkdirAll(filepath.Join(f.dir, "blobs", "sha256"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(f.dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0600))
	return f
}
func (f *fixture) blob(media string, b []byte) descriptor {
	f.t.Helper()
	sum := sha256.Sum256(b)
	digest := hex.EncodeToString(sum[:])
	require.NoError(f.t, os.WriteFile(filepath.Join(f.dir, "blobs", "sha256", digest), b, 0600))
	return descriptor{MediaType: media, Digest: "sha256:" + digest, Size: int64(len(b))}
}
func (f *fixture) json(media string, v any) descriptor {
	f.t.Helper()
	b, err := json.Marshal(v)
	require.NoError(f.t, err)
	return f.blob(media, b)
}
func (f *fixture) index(ds ...descriptor) {
	f.t.Helper()
	b, err := json.Marshal(manifest{SchemaVersion: 2, Manifests: ds})
	require.NoError(f.t, err)
	require.NoError(f.t, os.WriteFile(filepath.Join(f.dir, "index.json"), b, 0600))
}
func (f *fixture) image(arch string, layers ...descriptor) descriptor {
	cfg := f.json(imageConfig, map[string]any{"os": "linux", "architecture": arch, "config": map[string]any{"Env": []string{"TOKEN=config-secret"}}, "history": []any{map[string]string{"created_by": "RUN history-secret"}}})
	return f.json(imageManifest, manifest{SchemaVersion: 2, Config: cfg, Layers: layers})
}

type entry struct {
	name, content string
	kind          byte
}

func (f *fixture) layer(media string, entries ...entry) descriptor {
	f.t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range entries {
		kind := e.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		size := int64(len(e.content))
		if kind != tar.TypeReg && kind != tar.TypeGNUSparse {
			size = 0
		}
		require.NoError(f.t, tw.WriteHeader(&tar.Header{Name: e.name, Size: size, Mode: 0644, Typeflag: kind, Linkname: "app/key"}))
		if size > 0 {
			_, err := tw.Write([]byte(e.content))
			require.NoError(f.t, err)
		}
	}
	require.NoError(f.t, tw.Close())
	data := b.Bytes()
	encoding, err := compression(media)
	require.NoError(f.t, err)
	switch encoding {
	case "gzip":
		var out bytes.Buffer
		w := gzip.NewWriter(&out)
		_, err = w.Write(data)
		require.NoError(f.t, err)
		require.NoError(f.t, w.Close())
		data = out.Bytes()
	case "zstd":
		w, err := zstd.NewWriter(nil)
		require.NoError(f.t, err)
		data = w.EncodeAll(data, nil)
		w.Close()
	}
	return f.blob(media, data)
}
func collect(ctx context.Context, s *Layout) ([]sources.Fragment, error) {
	var mu sync.Mutex
	var got []sources.Fragment
	err := s.Fragments(ctx, func(f sources.Fragment, err error) error {
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		got = append(got, f)
		return nil
	})
	return got, err
}
func content(fs []sources.Fragment) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.Raw)
	}
	return b.String()
}

func TestLayoutStreamsLayersAndConfiguration(t *testing.T) {
	for _, media := range []string{layerTar, layerTar + "+gzip", layerTar + "+zstd", "application/vnd.docker.image.rootfs.diff.tar.gzip"} {
		t.Run(media, func(t *testing.T) {
			f := newFixture(t)
			old := f.layer(media, entry{"app/key", "deleted-secret", 0}, entry{"app/symlink", "", tar.TypeSymlink})
			newer := f.layer(media, entry{"app/.wh.key", "", 0}, entry{"app/live", "live-secret", 0})
			f.index(f.image("amd64", old, newer))
			// Unreferenced blobs must not contribute findings.
			f.blob(layerTar, []byte("unreferenced-secret"))
			got, err := collect(t.Context(), &Layout{Path: f.dir})
			require.NoError(t, err)
			all := content(got)
			for _, want := range []string{"deleted-secret", "live-secret", "config-secret", "history-secret"} {
				require.Contains(t, all, want)
			}
			require.NotContains(t, all, "unreferenced-secret")
			var layers int
			for _, fragment := range got {
				require.Equal(t, f.dir, fragment.Attr(AttrLayout))
				require.NotEmpty(t, fragment.Attr(AttrDigest))
				if fragment.Attr(sources.AttrResource) == ResourceLayer {
					layers++
					require.Contains(t, fragment.Attr(sources.AttrPath), "!app/")
					require.NotEmpty(t, fragment.Attr(AttrFilePath))
				}
			}
			require.Equal(t, 2, layers)
		})
	}
}
func TestLayoutSelectionAndSharedLayers(t *testing.T) {
	f := newFixture(t)
	shared := f.layer(layerTar, entry{"shared", "shared-secret", 0})
	a := f.image("amd64", shared, f.layer(layerTar, entry{"amd", "amd-secret", 0}))
	b := f.image("arm64", shared, f.layer(layerTar, entry{"arm", "arm-secret", 0}))
	a.Platform = &platform{OS: "linux", Architecture: "amd64"}
	b.Platform = &platform{OS: "linux", Architecture: "arm64"}
	idx := f.json(imageIndex, manifest{SchemaVersion: 2, Manifests: []descriptor{a, b}})
	idx.Annotations = map[string]string{"org.opencontainers.image.ref.name": "built"}
	other := f.image("s390x", f.layer(layerTar, entry{"other", "other-secret", 0}))
	other.Annotations = map[string]string{"org.opencontainers.image.ref.name": "other"}
	// BuildKit's non-image attestation descriptors are intentionally ignored.
	attestation := descriptor{Digest: "missing", Annotations: map[string]string{"vnd.docker.reference.type": "attestation-manifest"}}
	f.index(idx, other, attestation)
	got, err := collect(t.Context(), &Layout{Path: f.dir, Ref: "built"})
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(content(got), "shared-secret"))
	require.Contains(t, content(got), "amd-secret")
	require.Contains(t, content(got), "arm-secret")
	require.NotContains(t, content(got), "other-secret")
	got, err = collect(t.Context(), &Layout{Path: f.dir, Ref: "built", Platform: "linux/amd64"})
	require.NoError(t, err)
	require.Contains(t, content(got), "amd-secret")
	require.NotContains(t, content(got), "arm-secret")
	// A direct manifest without descriptor platform still uses config metadata.
	f.index(a, b)
	b.Platform = nil
	f.index(a, b)
	got, err = collect(t.Context(), &Layout{Path: f.dir, Platform: "linux/arm64"})
	require.NoError(t, err)
	require.Contains(t, content(got), "arm-secret")
	require.NotContains(t, content(got), "amd-secret")
	for _, s := range []*Layout{{Path: f.dir, Ref: "missing"}, {Path: f.dir, Platform: "linux/ppc64le"}} {
		_, err := collect(t.Context(), s)
		require.ErrorContains(t, err, "no OCI images")
	}
}
func TestLayoutCorruptionIsAnError(t *testing.T) {
	for _, test := range []string{"missing", "digest", "size", "gzip", "zstd", "tar", "path", "unsupported", "descriptor", "config", "escape"} {
		t.Run(test, func(t *testing.T) {
			f := newFixture(t)
			layer := f.layer(layerTar, entry{"app/key", "secret", 0})
			name := filepath.Join(f.dir, "blobs", "sha256", strings.TrimPrefix(layer.Digest, "sha256:"))
			switch test {
			case "missing":
				require.NoError(t, os.Remove(name))
			case "digest":
				data, err := os.ReadFile(name)
				require.NoError(t, err)
				data[512] = 'X'
				require.NoError(t, os.WriteFile(name, data, 0600))
			case "size":
				layer.Size++
			case "gzip":
				layer = f.blob(layerTar+"+gzip", []byte("not gzip"))
			case "zstd":
				layer = f.blob(layerTar+"+zstd", []byte("not zstd"))
			case "tar":
				layer = f.blob(layerTar, []byte("not tar"))
			case "path":
				layer = f.layer(layerTar, entry{"../../escape", "secret", 0})
			case "unsupported":
				layer.MediaType = "unsupported/layer"
			case "descriptor":
				layer.Digest = "sha256:../../escape"
			case "escape":
				require.NoError(t, os.Remove(name))
				outside := filepath.Join(t.TempDir(), "blob")
				require.NoError(t, os.WriteFile(outside, []byte("secret"), 0600))
				if err := os.Symlink(outside, name); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			m := f.image("amd64", layer)
			if test == "config" {
				cfg := f.blob(imageConfig, []byte("not JSON"))
				m = f.json(imageManifest, manifest{SchemaVersion: 2, Config: cfg})
			}
			f.index(m)
			_, err := collect(t.Context(), &Layout{Path: f.dir})
			require.Error(t, err)
		})
	}
}
func TestLayoutGzipFooterAndTruncatedEntry(t *testing.T) {
	f := newFixture(t)
	layer := f.layer(layerTar+"+gzip", entry{"app/key", "secret", 0})
	data, err := os.ReadFile(filepath.Join(f.dir, "blobs", "sha256", strings.TrimPrefix(layer.Digest, "sha256:")))
	require.NoError(t, err)
	// Valid descriptor digest for corrupt compressed data: checksum validation
	// must fail even though tar reaches its end marker before the gzip footer.
	data[len(data)-8] ^= 0xff
	layer = f.blob(layerTar+"+gzip", data)
	f.index(f.image("amd64", layer))
	_, err = collect(t.Context(), &Layout{Path: f.dir})
	require.Error(t, err)
	layer = f.layer(layerTar, entry{"app/key", strings.Repeat("X", 2048), 0})
	data, err = os.ReadFile(filepath.Join(f.dir, "blobs", "sha256", strings.TrimPrefix(layer.Digest, "sha256:")))
	require.NoError(t, err)
	layer = f.blob(layerTar, data[:600])
	f.index(f.image("amd64", layer))
	_, err = collect(t.Context(), &Layout{Path: f.dir})
	require.Error(t, err)
}
func TestLayoutArchiveDepthAndPrefilter(t *testing.T) {
	f := newFixture(t)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("inner.txt")
	require.NoError(t, err)
	_, err = w.Write([]byte("nested-secret"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	f.index(f.image("amd64", f.layer(layerTar+"+gzip", entry{"app/nested.zip", buf.String(), 0}, entry{"app/key", "plain-secret", 0})))
	got, err := collect(t.Context(), &Layout{Path: f.dir, MaxArchiveDepth: 0})
	require.NoError(t, err)
	require.Contains(t, content(got), "plain-secret")
	require.NotContains(t, content(got), "nested-secret")
	got, err = collect(t.Context(), &Layout{Path: f.dir, MaxArchiveDepth: 1})
	require.NoError(t, err)
	require.Contains(t, content(got), "nested-secret")
	got, err = collect(t.Context(), &Layout{Path: f.dir, MaxArchiveDepth: 1, Prefilter: func(a map[string]string) bool { return a[AttrFilePath] == "app/key" }})
	require.NoError(t, err)
	require.NotContains(t, content(got), "plain-secret")
	require.Contains(t, content(got), "nested-secret")
}
func TestLayoutStopsOnCancellationAndCallbackError(t *testing.T) {
	f := newFixture(t)
	f.index(f.image("amd64", f.layer(layerTar, entry{"app/key", strings.Repeat("line\n", 100000), 0})))
	s := &Layout{Path: f.dir}
	stop := errors.New("consumer stopped")
	err := s.Fragments(t.Context(), func(sources.Fragment, error) error { return stop })
	require.ErrorIs(t, err, stop)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err = s.Fragments(ctx, func(sources.Fragment, error) error { t.Error("yield after cancellation"); return nil })
	require.ErrorIs(t, err, context.Canceled)
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	err = s.Fragments(ctx, func(sources.Fragment, error) error { cancel(); return nil })
	require.ErrorIs(t, err, context.Canceled)
}
func TestLayoutRejectsInvalidEnvelope(t *testing.T) {
	for _, test := range []string{"version", "index", "schema", "empty", "platform", "depth"} {
		t.Run(test, func(t *testing.T) {
			f := newFixture(t)
			f.index()
			s := &Layout{Path: f.dir}
			switch test {
			case "version":
				require.NoError(t, os.WriteFile(filepath.Join(f.dir, "oci-layout"), []byte(`{"imageLayoutVersion":"2"}`), 0600))
			case "index":
				require.NoError(t, os.WriteFile(filepath.Join(f.dir, "index.json"), []byte("bad"), 0600))
			case "schema":
				require.NoError(t, os.WriteFile(filepath.Join(f.dir, "index.json"), []byte(`{"schemaVersion":1}`), 0600))
			case "platform":
				s.Platform = "amd64"
			case "depth":
				s.MaxArchiveDepth = -1
			}
			_, err := collect(t.Context(), s)
			require.Error(t, err)
		})
	}
}
func TestLayoutDeepIndex(t *testing.T) {
	f := newFixture(t)
	d := f.image("amd64")
	for i := 0; i < maxIndexDepth+2; i++ {
		d = f.json(imageIndex, manifest{SchemaVersion: 2, Manifests: []descriptor{d}})
	}
	f.index(d)
	_, err := collect(t.Context(), &Layout{Path: f.dir})
	require.ErrorContains(t, err, "nesting")
}

func TestLayoutDescriptorVariant(t *testing.T) {
	f := newFixture(t)
	d := f.image("arm64", f.layer(layerTar, entry{"app/key", "arm-secret", 0}))
	d.Platform = &platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	f.index(d)
	got, err := collect(t.Context(), &Layout{Path: f.dir, Platform: "linux/arm64/v8"})
	require.NoError(t, err)
	require.Contains(t, content(got), "arm-secret")
}

func TestLayoutConfigVariantCompletesPlatformSelection(t *testing.T) {
	f := newFixture(t)
	layer := f.layer(layerTar, entry{"app/key", "config-variant-secret", 0})
	config := f.json(imageConfig, map[string]any{
		"os":           "linux",
		"architecture": "arm64",
		"variant":      "v8",
	})
	image := f.json(imageManifest, manifest{
		SchemaVersion: 2,
		Config:        config,
		Layers:        []descriptor{layer},
	})
	image.Platform = &platform{OS: "linux", Architecture: "arm64"}
	f.index(image)

	got, err := collect(t.Context(), &Layout{Path: f.dir, Platform: "linux/arm64/v8"})
	require.NoError(t, err)
	require.Contains(t, content(got), "config-variant-secret")
}

func TestLayoutScansGNUSparseEntries(t *testing.T) {
	f := newFixture(t)
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "archive", "tar", "testdata", "gnu-nil-sparse-data.tar"))
	require.NoError(t, err)
	layer := f.blob(layerTar, data)
	f.index(f.image("amd64", layer))

	got, err := collect(t.Context(), &Layout{Path: f.dir})
	require.NoError(t, err)
	var found bool
	for _, fragment := range got {
		if fragment.Attr(AttrFilePath) == "sparse.db" {
			found = true
			break
		}
	}
	require.True(t, found)
}

func TestLayoutMaxLayerSize(t *testing.T) {
	for _, media := range []string{layerTar, layerTar + "+gzip", layerTar + "+zstd"} {
		t.Run(media, func(t *testing.T) {
			f := newFixture(t)
			layer := f.layer(media, entry{"key", "layer-secret", 0})
			f.index(f.image("amd64", layer))
			for _, limit := range []int64{0, 2048, 4096} {
				got, err := collect(t.Context(), &Layout{Path: f.dir, MaxLayerSize: limit})
				require.NoError(t, err)
				require.Contains(t, content(got), "layer-secret")
			}
			_, err := collect(t.Context(), &Layout{Path: f.dir, MaxLayerSize: 1024})
			require.ErrorContains(t, err, "OCI layer exceeds size limit of 1.0 KiB")
		})
	}
	t.Run("logical file size", func(t *testing.T) {
		f := newFixture(t)
		f.index(f.image("amd64", f.layer(layerTar, entry{"large-file", strings.Repeat("x", 1024), 0})))
		_, err := collect(t.Context(), &Layout{Path: f.dir, MaxLayerSize: 512})
		require.ErrorContains(t, err, `OCI layer file "large-file" exceeds size limit of 512 B`)
	})
	t.Run("trailing padding", func(t *testing.T) {
		f := newFixture(t)
		layer := f.layer(layerTar, entry{"key", "secret", 0})
		data, err := os.ReadFile(filepath.Join(f.dir, "blobs", "sha256", strings.TrimPrefix(layer.Digest, "sha256:")))
		require.NoError(t, err)
		limit := int64(len(data))
		layer = f.blob(layerTar, append(data, make([]byte, 512)...))
		f.index(f.image("amd64", layer))
		_, err = collect(t.Context(), &Layout{Path: f.dir, MaxLayerSize: limit})
		require.ErrorContains(t, err, "OCI layer exceeds size limit of 2.0 KiB")
	})
	t.Run("negative limit", func(t *testing.T) {
		_, err := collect(t.Context(), &Layout{MaxLayerSize: -1})
		require.EqualError(t, err, "OCI MaxLayerSize must not be negative")
	})
}

func TestBoundedReaderRejectsExpandedLayers(t *testing.T) {
	r := &boundedReader{reader: strings.NewReader("12345"), limit: 4}
	data, err := io.ReadAll(r)
	require.Equal(t, []byte("1234"), data)
	require.ErrorContains(t, err, "exceeds size limit")
}
func TestLayoutConflictingDescriptors(t *testing.T) {
	for _, kind := range []string{"manifest", "layer"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			layer := f.layer(layerTar, entry{"key", "secret", 0})
			d := f.image("amd64", layer)
			if kind == "manifest" {
				other := d
				other.Size++
				f.index(d, other)
			} else {
				other := layer
				other.Size++
				f.index(f.image("amd64", layer, other))
			}
			_, err := collect(t.Context(), &Layout{Path: f.dir})
			require.ErrorContains(t, err, "conflicting")
		})
	}
}

func TestLayoutSHA512Layer(t *testing.T) {
	f := newFixture(t)
	d := f.layer(layerTar, entry{"key", "sha512-secret", 0})
	data, err := os.ReadFile(filepath.Join(f.dir, "blobs", "sha256", strings.TrimPrefix(d.Digest, "sha256:")))
	require.NoError(t, err)
	sum := sha512.Sum512(data)
	encoded := hex.EncodeToString(sum[:])
	d.Digest = "sha512:" + encoded
	require.NoError(t, os.Mkdir(filepath.Join(f.dir, "blobs", "sha512"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(f.dir, "blobs", "sha512", encoded), data, 0600))
	f.index(f.image("amd64", d))
	got, err := collect(t.Context(), &Layout{Path: f.dir})
	require.NoError(t, err)
	require.Contains(t, content(got), "sha512-secret")
}
