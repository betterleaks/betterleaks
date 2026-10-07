package container

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/google/go-containerregistry/pkg/authn"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"
)

type tarEntry struct {
	name, content string
	kind          byte
	link          string
	pax           map[string]string
}

func tarBytes(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for _, e := range entries {
		kind := e.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Mode: 0600, Typeflag: kind, Linkname: e.link, PAXRecords: e.pax}
		if kind == tar.TypeReg {
			h.Size = int64(len(e.content))
		}
		require.NoError(t, w.WriteHeader(h))
		if h.Size > 0 {
			_, err := w.Write([]byte(e.content))
			require.NoError(t, err)
		}
	}
	require.NoError(t, w.Close())
	return buf.Bytes()
}
func jsonBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

type fixture struct {
	t     *testing.T
	blobs map[string][]byte
	index []byte
}

func newFixture(t *testing.T) *fixture { return &fixture{t: t, blobs: map[string][]byte{}} }
func (f *fixture) blob(data []byte, mt types.MediaType) v1.Descriptor {
	d := v1.Descriptor{Digest: sum(data), Size: int64(len(data)), MediaType: mt}
	f.blobs[d.Digest.String()] = data
	return d
}
func (f *fixture) image(arch string, layers [][]byte, encoding string) v1.Descriptor {
	var ds []v1.Descriptor
	var diffIDs []v1.Hash
	for _, raw := range layers {
		diffIDs = append(diffIDs, sum(raw))
		data := raw
		mt := types.OCIUncompressedLayer
		switch encoding {
		case "gzip":
			var buf bytes.Buffer
			w := gzip.NewWriter(&buf)
			_, err := w.Write(raw)
			require.NoError(f.t, err)
			require.NoError(f.t, w.Close())
			data = buf.Bytes()
			mt = types.OCILayer
		case "zstd":
			w, err := zstd.NewWriter(nil)
			require.NoError(f.t, err)
			data = w.EncodeAll(raw, nil)
			w.Close()
			mt = types.OCILayerZStd
		}
		ds = append(ds, f.blob(data, mt))
	}
	cfg := map[string]any{"architecture": arch, "os": "linux", "rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs}, "config": map[string]any{"Env": []string{"TOKEN=config-secret"}, "Labels": map[string]string{"secret": "label-secret"}, "Cmd": []string{"run", "command-secret"}}, "history": []map[string]any{{"created_by": "RUN history-secret"}, {"created_by": "ENV empty-history-secret", "empty_layer": true}}, "custom": map[string]string{"extension": "extension-secret", "pem": "-----BEGIN PRIVATE KEY-----\nprivate-secret\n-----END PRIVATE KEY-----"}}
	d := f.blob(jsonBytes(f.t, v1.Manifest{SchemaVersion: 2, MediaType: types.OCIManifestSchema1, Config: f.blob(jsonBytes(f.t, cfg), types.OCIConfigJSON), Layers: ds, Annotations: map[string]string{"secret": "manifest-secret"}}), types.OCIManifestSchema1)
	d.Platform = &v1.Platform{OS: "linux", Architecture: arch}
	return d
}
func (f *fixture) setIndex(ds ...v1.Descriptor) {
	f.index = jsonBytes(f.t, v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: ds, Annotations: map[string]string{"secret": "index-secret"}})
}
func (f *fixture) directory() string {
	dir := f.t.TempDir()
	require.NoError(f.t, os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0600))
	require.NoError(f.t, os.WriteFile(filepath.Join(dir, "index.json"), f.index, 0600))
	for digest, b := range f.blobs {
		parts := strings.Split(digest, ":")
		p := filepath.Join(dir, "blobs", parts[0], parts[1])
		require.NoError(f.t, os.MkdirAll(filepath.Dir(p), 0700))
		require.NoError(f.t, os.WriteFile(p, b, 0600))
	}
	return dir
}
func (f *fixture) archive() []byte {
	entries := []tarEntry{{name: "oci-layout", content: `{"imageLayoutVersion":"1.0.0"}`}, {name: "index.json", content: string(f.index)}}
	for digest, b := range f.blobs {
		entries = append(entries, tarEntry{name: "blobs/" + strings.ReplaceAll(digest, ":", "/"), content: string(b)})
	}
	return tarBytes(f.t, entries...)
}
func collect(t *testing.T, s *Source) ([]sources.Fragment, []error) {
	t.Helper()
	var fragments []sources.Fragment
	var errs []error
	err := s.Fragments(t.Context(), func(f sources.Fragment, err error) error {
		if err != nil {
			errs = append(errs, err)
		} else {
			fragments = append(fragments, f)
		}
		return nil
	})
	if err != nil {
		errs = append(errs, err)
	}
	return fragments, errs
}
func find(t *testing.T, fs []sources.Fragment, resource, path, content string) *sources.Fragment {
	t.Helper()
	for _, f := range fs {
		if f.Attr(sources.AttrResource) == resource && (path == "" || f.Attr(sources.AttrPath) == path) && strings.Contains(f.Raw, content) {
			return &f
		}
	}
	t.Fatalf("missing fragment resource=%s path=%s content=%s", resource, path, content)
	return nil
}

func TestAllPlatformsLayersAndMetadata(t *testing.T) {
	for _, encoding := range []string{"tar", "gzip", "zstd"} {
		t.Run(encoding, func(t *testing.T) {
			f := newFixture(t)
			lower := tarBytes(t, tarEntry{name: "removed", content: "deleted-secret"}, tarEntry{name: "replaced", content: "old-secret"}, tarEntry{name: "opaque/old", content: "opaque-secret"}, tarEntry{name: "visible", content: "visible-secret"})
			upper := tarBytes(t, tarEntry{name: ".wh.removed"}, tarEntry{name: "replaced", content: "new-secret"}, tarEntry{name: "opaque/new", content: "new-opaque-secret"}, tarEntry{name: "opaque/.wh..wh..opq"}, tarEntry{name: "link", kind: tar.TypeSymlink, link: "link-secret", pax: map[string]string{"SCHILY.xattr.user.token": "xattr-secret"}})
			amd := f.image("amd64", [][]byte{lower, upper}, encoding)
			arm := f.image("arm64", [][]byte{tarBytes(t, tarEntry{name: "arm", content: "arm-only-secret"})}, encoding)
			artifact := f.blob(jsonBytes(t, v1.Manifest{SchemaVersion: 2, MediaType: types.OCIManifestSchema1, Config: f.blob([]byte("{}"), types.OCIEmptyJSON), Layers: []v1.Descriptor{f.blob([]byte(`{"predicate":{"secret":"attestation-secret"}}`), "application/vnd.in-toto+json")}}), types.OCIManifestSchema1)
			artifact.Platform = &v1.Platform{OS: "unknown", Architecture: "unknown"}
			f.setIndex(amd, arm, artifact)
			fs, errs := collect(t, &Source{Layouts: []string{f.directory()}, MaxArchiveDepth: 8})
			require.Empty(t, errs)
			for p, want := range map[string]string{"/removed": "deleted", "/replaced": "overwritten", "/opaque/old": "deleted", "/visible": "visible"} {
				content := ""
				if p == "/replaced" {
					content = "old-secret"
				}
				got := find(t, fs, ResourceFile, p, content)
				require.Equal(t, want, got.Attr(AttrPathState))
				require.Equal(t, "0", got.Attr(AttrLayerIndex))
				require.Equal(t, amd.Digest.String(), got.Attr(AttrDigest))
				require.Equal(t, "linux/amd64", got.Attr(AttrPlatform))
				if want != "visible" {
					require.NotEmpty(t, got.Attr(AttrHiddenByLayer))
				}
			}
			require.Equal(t, "visible", find(t, fs, ResourceFile, "/opaque/new", "").Attr(AttrPathState))
			find(t, fs, ResourceFile, "/arm", "arm-only-secret")
			for _, secret := range []string{"config-secret", "label-secret", "command-secret", "extension-secret", "-----BEGIN PRIVATE KEY-----\nprivate-secret"} {
				find(t, fs, ResourceConfig, "", secret)
			}
			find(t, fs, ResourceIndex, "@index", "index-secret")
			find(t, fs, ResourceManifest, "@manifest", "manifest-secret")
			h := find(t, fs, ResourceHistory, "@history/0", "history-secret")
			require.Equal(t, "0", h.Attr(AttrLayerIndex))
			require.NotEmpty(t, h.Attr(AttrLayerDigest))
			require.Empty(t, find(t, fs, ResourceHistory, "@history/1", "empty-history-secret").Attr(AttrLayerDigest))
			find(t, fs, ResourceArtifact, "", "attestation-secret")
			find(t, fs, ResourceLayerMetadata, "/link", "link-secret")
			find(t, fs, ResourceLayerMetadata, "/link", "xattr-secret")
		})
	}
}

func TestNestedArchivesAndStrictCoverage(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	item, err := w.Create("secret.txt")
	require.NoError(t, err)
	_, err = item.Write([]byte("nested-secret"))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	f := newFixture(t)
	f.setIndex(f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "opaque-name", content: buf.String()})}, "tar"))
	dir := f.directory()
	fs, errs := collect(t, &Source{Layouts: []string{dir}, MaxArchiveDepth: 8})
	require.Empty(t, errs)
	find(t, fs, ResourceFile, "/opaque-name!secret.txt", "nested-secret")
	_, errs = collect(t, &Source{Layouts: []string{dir}})
	require.NotEmpty(t, errs)
	require.Contains(t, errs[0].Error(), "archive depth")
	_, errs = collect(t, &Source{Layouts: []string{dir}, MaxArchiveDepth: 8, MaxFileSize: 1})
	require.NotEmpty(t, errs)
	require.Contains(t, errs[0].Error(), "max-file-size")
	f = newFixture(t)
	f.setIndex(f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "broken.zip", content: "PK\x03\x04corrupt"})}, "tar"))
	_, errs = collect(t, &Source{Layouts: []string{f.directory()}, MaxArchiveDepth: 8})
	require.NotEmpty(t, errs)
}

func TestPrefilterReceivesProvenance(t *testing.T) {
	f := newFixture(t)
	f.setIndex(f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "secret", content: "must-skip"})}, "tar"))
	fs, errs := collect(t, &Source{Layouts: []string{f.directory()}, Prefilter: func(a map[string]string) bool {
		return a[AttrPlatform] == "linux/amd64" && a[sources.AttrResource] == ResourceFile && a[sources.AttrPath] == "/secret"
	}})
	require.Empty(t, errs)
	for _, f := range fs {
		require.NotContains(t, f.Raw, "must-skip")
	}
}

func TestCallbackStopAndCancellation(t *testing.T) {
	f := newFixture(t)
	f.setIndex(f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "secret", content: "secret"})}, "tar"))
	dir := f.directory()
	want := errors.New("stop")
	for _, at := range []int{1, 4, 7} {
		calls := 0
		err := (&Source{Layouts: []string{dir, dir}}).Fragments(t.Context(), func(sources.Fragment, error) error {
			calls++
			if calls == at {
				return want
			}
			return nil
		})
		require.ErrorIs(t, err, want)
		require.Equal(t, at, calls)
	}
	ctx, cancel := context.WithCancel(t.Context())
	calls := 0
	err := (&Source{Layouts: []string{dir}}).Fragments(ctx, func(sources.Fragment, error) error { calls++; cancel(); return nil })
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, calls)
}

func TestCorruptLayerDoesNotHideOtherImages(t *testing.T) {
	f := newFixture(t)
	amd := f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "lower", content: "lower-secret"}), tarBytes(t, tarEntry{name: "top", content: "top-secret"})}, "gzip")
	var manifest v1.Manifest
	require.NoError(t, json.Unmarshal(f.blobs[amd.Digest.String()], &manifest))
	f.blobs[manifest.Layers[1].Digest.String()] = []byte("corrupt")
	f.setIndex(amd, f.image("arm64", [][]byte{tarBytes(t, tarEntry{name: "arm", content: "arm-secret"})}, "tar"))
	fs, errs := collect(t, &Source{Layouts: []string{f.directory()}})
	require.NotEmpty(t, errs)
	require.Equal(t, "unknown", find(t, fs, ResourceFile, "/lower", "lower-secret").Attr(AttrPathState))
	find(t, fs, ResourceFile, "/arm", "arm-secret")
}

func TestDigestMismatch(t *testing.T) {
	f := newFixture(t)
	d := f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "file", content: "value"})}, "tar")
	f.setIndex(d)
	var m v1.Manifest
	require.NoError(t, json.Unmarshal(f.blobs[d.Digest.String()], &m))
	data := bytes.Clone(f.blobs[m.Layers[0].Digest.String()])
	data[512] = 'X'
	f.blobs[m.Layers[0].Digest.String()] = data
	_, errs := collect(t, &Source{Layouts: []string{f.directory()}})
	require.NotEmpty(t, errs)
	require.Contains(t, errs[0].Error(), "digest mismatch")
}

func TestRegistryNestedIndexAndPlatformSelection(t *testing.T) {
	f := newFixture(t)
	amd := f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "amd", content: "amd-secret"})}, "gzip")
	arm := f.image("arm64", [][]byte{tarBytes(t, tarEntry{name: "arm", content: "arm-secret"})}, "zstd")
	f.setIndex(amd, arm)
	nested := f.blob(f.index, types.OCIImageIndex)
	f.setIndex(nested)
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		if req.URL.Path == "/v2/" {
			w.WriteHeader(200)
			return
		}
		var b []byte
		if strings.HasSuffix(req.URL.Path, "/manifests/latest") {
			b = f.index
			w.Header().Set("Content-Type", string(types.OCIImageIndex))
		} else {
			key := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
			b = f.blobs[key]
			if strings.Contains(req.URL.Path, "/manifests/") {
				var e struct {
					MediaType string `json:"mediaType"`
				}
				_ = json.Unmarshal(b, &e)
				w.Header().Set("Content-Type", e.MediaType)
			}
		}
		if b == nil {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		_, _ = w.Write(b)
	}))
	defer server.Close()
	ref := strings.TrimPrefix(server.URL, "http://") + "/test:latest"
	for _, platforms := range [][]string{nil, {"linux/arm64"}, {"windows/amd64"}} {
		fs, errs := collect(t, &Source{Images: []string{ref}, Anonymous: true, PlainHTTP: true, Platforms: platforms})
		if len(platforms) > 0 && platforms[0] == "windows/amd64" {
			require.NotEmpty(t, errs)
			continue
		}
		require.Empty(t, errs)
		find(t, fs, ResourceFile, "/arm", "arm-secret")
		if len(platforms) == 0 {
			find(t, fs, ResourceFile, "/amd", "amd-secret")
		} else {
			for _, f := range fs {
				require.NotContains(t, f.Raw, "amd-secret")
			}
		}
	}
	require.Positive(t, requests.Load())
}

func TestArchives(t *testing.T) {
	f := newFixture(t)
	f.setIndex(f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "secret", content: "archive-secret"})}, "gzip"))
	for _, compressed := range []bool{false, true} {
		data := f.archive()
		if compressed {
			var b bytes.Buffer
			w := gzip.NewWriter(&b)
			_, err := w.Write(data)
			require.NoError(t, err)
			require.NoError(t, w.Close())
			data = b.Bytes()
		}
		p := filepath.Join(t.TempDir(), "image.tar")
		require.NoError(t, os.WriteFile(p, data, 0600))
		fs, errs := collect(t, &Source{Archives: []string{p}})
		require.Empty(t, errs)
		find(t, fs, ResourceFile, "/secret", "archive-secret")
		_, errs = collect(t, &Source{Archives: []string{p}, MaxArchiveSize: 10})
		require.NotEmpty(t, errs)
	}
}

func TestDockerArchiveMultipleUntaggedImages(t *testing.T) {
	var entries []tarEntry
	var manifest []map[string]any
	for i, arch := range []string{"amd64", "arm64"} {
		layer := tarBytes(t, tarEntry{name: "secret", content: arch + "-secret"})
		cfg := jsonBytes(t, map[string]any{"os": "linux", "architecture": arch, "rootfs": map[string]any{"type": "layers", "diff_ids": []string{sum(layer).String()}}})
		configPath := fmt.Sprintf("%d/config.json", i)
		layerPath := fmt.Sprintf("%d/layer.tar", i)
		entries = append(entries, tarEntry{name: configPath, content: string(cfg)}, tarEntry{name: layerPath, content: string(layer)})
		manifest = append(manifest, map[string]any{"Config": configPath, "Layers": []string{layerPath}, "RepoTags": []string{}})
	}
	entries = append(entries, tarEntry{name: "manifest.json", content: string(jsonBytes(t, manifest))})
	p := filepath.Join(t.TempDir(), "docker.tar")
	require.NoError(t, os.WriteFile(p, tarBytes(t, entries...), 0600))
	fs, errs := collect(t, &Source{Archives: []string{p}})
	require.Empty(t, errs)
	for _, arch := range []string{"amd64", "arm64"} {
		f := find(t, fs, ResourceFile, "/secret", arch+"-secret")
		require.Empty(t, f.Attr(AttrDigest))
		require.Empty(t, f.Attr(AttrLayerDigest))
		require.NotEmpty(t, f.Attr(AttrDiffID))
		require.NotEmpty(t, f.Attr(AttrConfigDigest))
	}
}

func TestUnsafeArchiveEntries(t *testing.T) {
	for _, entry := range []tarEntry{{name: "../escape", content: "bad"}, {name: "/absolute", content: "bad"}, {name: "link", kind: tar.TypeSymlink, link: "/tmp"}, {name: "link", kind: tar.TypeLink, link: "/etc/passwd"}} {
		t.Run(entry.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "image.tar")
			require.NoError(t, os.WriteFile(p, tarBytes(t, entry), 0600))
			_, errs := collect(t, &Source{Archives: []string{p}})
			require.NotEmpty(t, errs)
		})
	}
}

func TestLayerLinksNeverFollowHostFiles(t *testing.T) {
	p := filepath.Join(t.TempDir(), "host-secret")
	require.NoError(t, os.WriteFile(p, []byte("host-contents-must-not-be-read"), 0600))
	f := newFixture(t)
	f.setIndex(f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "symlink", kind: tar.TypeSymlink, link: p}, tarEntry{name: "hardlink", kind: tar.TypeLink, link: p})}, "tar"))
	fs, errs := collect(t, &Source{Layouts: []string{f.directory()}})
	require.Empty(t, errs)
	for _, f := range fs {
		require.NotContains(t, f.Raw, "host-contents-must-not-be-read")
	}
}

func TestVerifiedReaderAlgorithms(t *testing.T) {
	for _, digest := range []v1.Hash{{Algorithm: "md5", Hex: "abc"}, {Algorithm: "sha256", Hex: "bad"}} {
		_, err := verifyingReader(strings.NewReader("x"), digest)
		require.Error(t, err)
	}
	r, err := verifyingReader(strings.NewReader("wrong"), sum([]byte("right")))
	require.NoError(t, err)
	_, err = io.ReadAll(r)
	require.ErrorContains(t, err, "digest mismatch")
}

func TestOverlayDirectoryReplacementAndWhiteouts(t *testing.T) {
	f := newFixture(t)
	layers := [][]byte{
		tarBytes(t, tarEntry{name: "dir/old", content: "old-secret"}, tarEntry{name: "dir2/old", content: "old-secret-2"}, tarEntry{name: "same", content: "same-old"}, tarEntry{name: "other", content: "other-secret"}),
		tarBytes(t, tarEntry{name: "dir", content: "replacement-file"}, tarEntry{name: "dir2/old", content: "replacement-secret"}),
		tarBytes(t, tarEntry{name: "dir/", kind: tar.TypeDir}, tarEntry{name: "dir/new", content: "new-secret"}, tarEntry{name: ".wh.dir2"}, tarEntry{name: ".wh.same"}, tarEntry{name: "same", content: "same-new"}),
	}
	f.setIndex(f.image("amd64", layers, "tar"))
	fs, errs := collect(t, &Source{Layouts: []string{f.directory()}})
	require.Empty(t, errs)
	require.Equal(t, "overwritten", find(t, fs, ResourceFile, "/dir/old", "").Attr(AttrPathState))
	require.Equal(t, "overwritten", find(t, fs, ResourceFile, "/dir2/old", "old-secret-2").Attr(AttrPathState))
	require.Equal(t, "deleted", find(t, fs, ResourceFile, "/dir2/old", "replacement-secret").Attr(AttrPathState))
	require.Equal(t, "visible", find(t, fs, ResourceFile, "/same", "same-new").Attr(AttrPathState))
	require.NotEqual(t, "visible", find(t, fs, ResourceFile, "/same", "same-old").Attr(AttrPathState))
	require.Equal(t, "visible", find(t, fs, ResourceFile, "/other", "").Attr(AttrPathState))
}

func TestLayerValidation(t *testing.T) {
	for label, entries := range map[string][]tarEntry{
		"duplicate":           {{name: "a", content: "first"}, {name: "./a", content: "second"}},
		"traversal":           {{name: "../outside", content: "secret"}},
		"empty whiteout name": {{name: ".wh."}},
		"nonempty whiteout":   {{name: ".wh.secret", content: "invalid"}},
	} {
		t.Run(label, func(t *testing.T) {
			f := newFixture(t)
			f.setIndex(f.image("amd64", [][]byte{tarBytes(t, entries...)}, "tar"))
			_, errs := collect(t, &Source{Layouts: []string{f.directory()}})
			require.NotEmpty(t, errs)
		})
	}
}

func TestLargeFilesHaveNoImplicitCutoff(t *testing.T) {
	if testing.Short() {
		t.Skip("large streaming fixture")
	}
	f := newFixture(t)
	data := strings.Repeat("filler line\n", (51<<20)/12) + "large-file-secret\n"
	f.setIndex(f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "large.txt", content: data})}, "gzip"))
	dir := f.directory()
	found := false
	err := (&Source{Layouts: []string{dir}}).Fragments(t.Context(), func(f sources.Fragment, err error) error {
		require.NoError(t, err)
		if strings.Contains(f.Raw, "large-file-secret") {
			found = true
		}
		return nil
	})
	require.NoError(t, err)
	require.True(t, found)
}

func TestRootDirectoryMetadata(t *testing.T) {
	f := newFixture(t)
	f.setIndex(f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "./", kind: tar.TypeDir, pax: map[string]string{"SCHILY.xattr.user.secret": "root-xattr-secret"}})}, "tar"))
	fs, errs := collect(t, &Source{Layouts: []string{f.directory()}})
	require.Empty(t, errs)
	find(t, fs, ResourceLayerMetadata, "/", "root-xattr-secret")
}

func TestInlineOCIDescriptors(t *testing.T) {
	f := newFixture(t)
	d := f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "inline", content: "inline-secret"})}, "tar")
	var manifest v1.Manifest
	require.NoError(t, json.Unmarshal(f.blobs[d.Digest.String()], &manifest))
	manifest.Config.Data = f.blobs[manifest.Config.Digest.String()]
	for i := range manifest.Layers {
		manifest.Layers[i].Data = f.blobs[manifest.Layers[i].Digest.String()]
	}
	d = f.blob(jsonBytes(t, manifest), types.OCIManifestSchema1)
	d.Data = f.blobs[d.Digest.String()]
	f.setIndex(d)
	f.blobs = map[string][]byte{}
	fs, errs := collect(t, &Source{Layouts: []string{f.directory()}})
	require.Empty(t, errs)
	find(t, fs, ResourceFile, "/inline", "inline-secret")
}

func TestLayoutSymlinkEscape(t *testing.T) {
	f := newFixture(t)
	d := f.image("amd64", nil, "tar")
	f.setIndex(d)
	dir := f.directory()
	blob := filepath.Join(dir, "blobs", d.Digest.Algorithm, d.Digest.Hex)
	require.NoError(t, os.Remove(blob))
	outside := filepath.Join(t.TempDir(), "manifest")
	require.NoError(t, os.WriteFile(outside, f.blobs[d.Digest.String()], 0600))
	if err := os.Symlink(outside, blob); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	_, errs := collect(t, &Source{Layouts: []string{dir}})
	require.NotEmpty(t, errs)
}

func TestMissingConfigStillScansLayers(t *testing.T) {
	f := newFixture(t)
	d := f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "file", content: "recoverable-secret"})}, "gzip")
	var manifest v1.Manifest
	require.NoError(t, json.Unmarshal(f.blobs[d.Digest.String()], &manifest))
	delete(f.blobs, manifest.Config.Digest.String())
	f.setIndex(d)
	fs, errs := collect(t, &Source{Layouts: []string{f.directory()}})
	require.NotEmpty(t, errs)
	find(t, fs, ResourceFile, "/file", "recoverable-secret")
	find(t, fs, ResourceManifest, "@manifest", "manifest-secret")
}

func TestMetadataPreservesJSONAndDecodedStrings(t *testing.T) {
	var fs []sources.Fragment
	r := &session{s: &Source{}, yield: func(f sources.Fragment, err error) error { require.NoError(t, err); fs = append(fs, f); return nil }}
	// Deliberately invalid key material tests JSON shape and escape handling.
	raw := []byte(`{"credential":{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nkey-secret\n-----END PRIVATE KEY-----","auth_provider_x509_cert_url":"https://example.test/certs"},"env":["TOKEN=\u0073ecret"]}`)
	require.NoError(t, r.metadata(t.Context(), raw, "@config", ResourceConfig, map[string]string{AttrImage: "example"}))
	original := find(t, fs, ResourceConfig, "@config", `"type":"service_account"`)
	require.JSONEq(t, string(raw), original.Raw)
	require.Equal(t, "json", original.Attr(AttrRepresentation))
	decoded := find(t, fs, ResourceConfig, "@config#decoded", "-----BEGIN PRIVATE KEY-----\nkey-secret")
	require.Contains(t, decoded.Raw, "TOKEN=secret")
	require.Equal(t, "decoded", decoded.Attr(AttrRepresentation))
	require.Error(t, r.metadata(t.Context(), []byte(`{} trailing-secret`), "@config", ResourceConfig, nil))
}

type fixedKeychain struct{ calls atomic.Int64 }

func (k *fixedKeychain) Resolve(authn.Resource) (authn.Authenticator, error) {
	k.calls.Add(1)
	return authn.FromConfig(authn.AuthConfig{Username: "test-user", Password: "test-password"}), nil
}

func TestRegistryAuthenticationAndAnonymous(t *testing.T) {
	f := newFixture(t)
	d := f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "file", content: "private-secret"})}, "tar")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		user, password, ok := req.BasicAuth()
		if !ok || user != "test-user" || password != "test-password" {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(401)
			return
		}
		if req.URL.Path == "/v2/" {
			w.WriteHeader(200)
			return
		}
		key := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
		if key == "latest" {
			key = d.Digest.String()
			w.Header().Set("Content-Type", string(types.OCIManifestSchema1))
		}
		b := f.blobs[key]
		if b == nil {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		_, _ = w.Write(b)
	}))
	defer server.Close()
	k := &fixedKeychain{}
	ref := strings.TrimPrefix(server.URL, "http://") + "/private:latest"
	fs, errs := collect(t, &Source{Images: []string{ref}, PlainHTTP: true, Keychain: k})
	require.Empty(t, errs)
	find(t, fs, ResourceFile, "/file", "private-secret")
	require.Positive(t, k.calls.Load())
	k.calls.Store(0)
	_, errs = collect(t, &Source{Images: []string{ref}, PlainHTTP: true, Keychain: k, Anonymous: true})
	require.NotEmpty(t, errs)
	require.Zero(t, k.calls.Load())
}

func TestDaemonValidation(t *testing.T) {
	for _, daemon := range []string{"", "docker", "podman"} {
		require.NoError(t, (&Source{Images: []string{"example:local"}, Daemon: daemon}).Validate())
	}
	for _, daemon := range []string{"unknown", "/usr/bin/docker", "docker image save"} {
		err := (&Source{Images: []string{"example:local"}, Daemon: daemon}).Validate()
		require.ErrorContains(t, err, "expected docker or podman")
	}
	for _, daemon := range []string{"docker", "podman"} {
		err := (&Source{Archives: []string{"image.tar"}, Daemon: daemon}).Validate()
		require.ErrorContains(t, err, "requires an image reference")
	}
}

func TestDaemonExportAndTemporaryCleanup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mock container CLI")
	}
	for _, daemon := range []string{"docker", "podman"} {
		t.Run(daemon, func(t *testing.T) {
			f := newFixture(t)
			f.setIndex(f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "file", content: "daemon-secret"})}, "gzip"))
			dir := t.TempDir()
			archive := filepath.Join(dir, "input.tar")
			require.NoError(t, os.WriteFile(archive, f.archive(), 0600))
			// The mock verifies argv and exports a real OCI image archive. No daemon
			// is required, and a nonzero CLI exit is tested after valid content.
			script := "#!/bin/sh\n[ \"$1\" = image ] && [ \"$2\" = save ] && [ \"$3\" = -- ] && [ \"$4\" = example:local ] || exit 2\ncat \"$CONTAINER_TEST_ARCHIVE\"\nexit \"${CONTAINER_TEST_EXIT:-0}\"\n"
			require.NoError(t, os.WriteFile(filepath.Join(dir, daemon), []byte(script), 0700))
			for _, other := range []string{"docker", "podman"} {
				if other != daemon {
					require.NoError(t, os.WriteFile(filepath.Join(dir, other), []byte("#!/bin/sh\nexit 99\n"), 0700))
				}
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("CONTAINER_TEST_ARCHIVE", archive)
			temp := t.TempDir()
			t.Setenv("TMPDIR", temp)
			fs, errs := collect(t, &Source{Images: []string{"example:local"}, Daemon: daemon})
			require.Empty(t, errs)
			found := find(t, fs, ResourceFile, "/file", "daemon-secret")
			require.Equal(t, "daemon:"+daemon+":example:local", found.Attr(AttrImage))
			t.Setenv("CONTAINER_TEST_EXIT", "9")
			_, errs = collect(t, &Source{Images: []string{"example:local"}, Daemon: daemon})
			require.NotEmpty(t, errs)
			files, err := os.ReadDir(temp)
			require.NoError(t, err)
			require.Empty(t, files)
		})
	}
}
