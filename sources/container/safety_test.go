package container

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/sources"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"
)

//nolint:exhaustruct // Fixtures set only the fields relevant to each scenario.
func TestOuterArchiveAliases(t *testing.T) {
	alias := tarEntry{name: "legacy/layer.tar", kind: tar.TypeSymlink, link: "../physical.tar"}
	physical := tarEntry{name: "physical.tar", content: "layer bytes"}
	for _, tc := range []struct {
		name    string
		entries []tarEntry
		valid   bool
	}{
		{"forward", []tarEntry{alias, physical}, true},
		{"backward", []tarEntry{physical, alias}, true},
		{"chain", []tarEntry{{name: "second/layer.tar", kind: tar.TypeSymlink, link: "../legacy/layer.tar"}, alias, physical}, true},
		{"absolute", []tarEntry{{name: alias.name, kind: tar.TypeSymlink, link: "/etc/passwd"}}, false},
		{"escape", []tarEntry{{name: alias.name, kind: tar.TypeSymlink, link: "../../outside"}}, false},
		{"backslash", []tarEntry{{name: alias.name, kind: tar.TypeSymlink, link: `..\outside`}}, false},
		{"volume", []tarEntry{{name: alias.name, kind: tar.TypeSymlink, link: "C:/outside"}}, false},
		{"hardlink-relative-root", []tarEntry{{name: alias.name, kind: tar.TypeLink, link: "../physical.tar"}, physical}, false},
		{"missing", []tarEntry{alias}, false},
		{"directory", []tarEntry{alias, {name: "physical.tar", kind: tar.TypeDir}}, false},
		{"self", []tarEntry{{name: alias.name, kind: tar.TypeSymlink, link: "layer.tar"}}, false},
		{"cycle", []tarEntry{{name: alias.name, kind: tar.TypeSymlink, link: "../other/layer.tar"}, {name: "other/layer.tar", kind: tar.TypeSymlink, link: "../legacy/layer.tar"}}, false},
		{"duplicate-alias", []tarEntry{alias, alias, physical}, false},
		{"alias-then-file", []tarEntry{alias, {name: alias.name, content: "overwrite"}, physical}, false},
		{"file-then-alias", []tarEntry{{name: alias.name, content: "overwrite"}, alias, physical}, false},
		{"alias-then-child", []tarEntry{alias, {name: alias.name + "/child"}, physical}, false},
		{"child-then-alias", []tarEntry{{name: alias.name + "/child"}, alias, physical}, false},
		{"alias-then-directory", []tarEntry{alias, {name: alias.name, kind: tar.TypeDir}, physical}, false},
		{"directory-then-alias", []tarEntry{{name: alias.name, kind: tar.TypeDir}, alias, physical}, false},
		{"nested-alias", []tarEntry{{name: alias.name + "/child/layer.tar", kind: tar.TypeLink, link: "physical.tar"}, alias, physical}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, err := os.OpenRoot(t.TempDir())
			require.NoError(t, err)
			defer root.Close()
			aliases := make(map[string]string)
			r := &session{s: &Source{}}
			err = r.unpackFiles(t.Context(), bytes.NewReader(tarBytes(t, tc.entries...)), root, "test", aliases)
			if !tc.valid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			for name := range aliases {
				_, err := root.Lstat(name)
				require.ErrorIs(t, err, os.ErrNotExist, "aliases must not become filesystem entries")
			}
			data, err := root.ReadFile("physical.tar")
			require.NoError(t, err)
			require.Equal(t, physical.content, string(data))
		})
	}
	for _, depth := range []int{32, 33} {
		t.Run(fmt.Sprintf("depth-%d", depth), func(t *testing.T) {
			entries := []tarEntry{physical}
			target := "physical.tar"
			for i := 0; i < depth; i++ {
				name := fmt.Sprintf("%d/layer.tar", i)
				entries = append(entries, tarEntry{name: name, kind: tar.TypeLink, link: target})
				target = name
			}
			root, err := os.OpenRoot(t.TempDir())
			require.NoError(t, err)
			defer root.Close()
			r := &session{s: &Source{}}
			err = r.unpackFiles(t.Context(), bytes.NewReader(tarBytes(t, entries...)), root, "test", make(map[string]string))
			if depth == 32 {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "exceeds 32 links")
			}
		})
	}
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, err := w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return b.Bytes()
}

func TestNestedCompressionAndDepth(t *testing.T) {
	const secret = "NESTED_TEST_SECRET_abc123"
	f := newFixture(t)
	f.setIndex(f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "payload.gz.gz", content: string(gzipBytes(t, gzipBytes(t, []byte(secret))))})}, "tar"))
	dir := f.directory()
	fs, errs := collect(t, &Source{Layouts: []string{dir}, MaxArchiveDepth: 2})
	require.Empty(t, errs)
	find(t, fs, ResourceFile, "/payload.gz.gz", secret)
	_, errs = collect(t, &Source{Layouts: []string{dir}, MaxArchiveDepth: 1})
	require.NotEmpty(t, errs)
	require.ErrorContains(t, errs[0], "archive depth")
	stop := errors.New("consumer stopped")
	calls := 0
	err := (&Source{Layouts: []string{dir}, MaxArchiveDepth: 8}).Fragments(t.Context(), func(fragment sources.Fragment, err error) error {
		require.NoError(t, err)
		if fragment.Attr(sources.AttrResource) == ResourceFile {
			calls++
			return stop
		}
		return nil
	})
	require.ErrorIs(t, err, stop)
	require.Equal(t, 1, calls)
}

func TestArtifactDescriptorSizes(t *testing.T) {
	for _, size := range []int64{-1, 0, 1, 4095, 4096, 4097} {
		for _, limit := range []int64{16, 4096, 0} {
			t.Run(fmt.Sprintf("size=%d/limit=%d", size, limit), func(t *testing.T) {
				f := newFixture(t)
				payload := f.blob([]byte(strings.Repeat("x", 4096)), "application/octet-stream")
				payload.Size = size
				d := f.blob(jsonBytes(t, v1.Manifest{SchemaVersion: 2, MediaType: types.OCIManifestSchema1, Config: f.blob([]byte("{}"), types.OCIEmptyJSON), Layers: []v1.Descriptor{payload}}), types.OCIManifestSchema1)
				f.setIndex(d)
				fs, errs := collect(t, &Source{Layouts: []string{f.directory()}, MaxFileSize: limit, MaxArchiveDepth: 8})
				if size == 4096 && limit != 16 {
					require.Empty(t, errs)
				} else {
					require.NotEmpty(t, errs)
				}
				emitted := 0
				for _, v := range fs {
					if v.Attr(sources.AttrResource) == ResourceArtifact {
						emitted += len(v.Raw)
					}
				}
				if limit > 0 {
					require.LessOrEqual(t, int64(emitted), limit)
				}
			})
		}
	}
}

func TestManifestAndConfigDescriptorSizes(t *testing.T) {
	for _, part := range []string{"manifest", "config", "layer"} {
		t.Run(part, func(t *testing.T) {
			f := newFixture(t)
			d := f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "file", content: "content"})}, "gzip")
			if part == "manifest" {
				d.Size++
			} else {
				var m v1.Manifest
				require.NoError(t, json.Unmarshal(f.blobs[d.Digest.String()], &m))
				if part == "config" {
					m.Config.Size++
				} else {
					m.Layers[0].Size++
				}
				d = f.blob(jsonBytes(t, m), types.OCIManifestSchema1)
			}
			f.setIndex(d)
			_, errs := collect(t, &Source{Layouts: []string{f.directory()}})
			require.NotEmpty(t, errs)
			require.Contains(t, fmt.Sprint(errs), "size")
		})
	}
}

func TestPlatformSelectionWithoutDescriptorPlatform(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(fmt.Sprintf("nested=%v", nested), func(t *testing.T) {
			f := newFixture(t)
			amd := f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "amd", content: "amd-content"})}, "tar")
			arm := f.image("arm64", [][]byte{tarBytes(t, tarEntry{name: "arm", content: "arm-content"})}, "tar")
			amd.Platform = nil
			arm.Platform = nil
			if nested {
				arm = f.blob(jsonBytes(t, v1.IndexManifest{SchemaVersion: 2, Manifests: []v1.Descriptor{arm}}), types.OCIImageIndex)
			}
			f.setIndex(amd, arm)
			dir := f.directory()
			fs, errs := collect(t, &Source{Layouts: []string{dir}, Platforms: []string{"linux/amd64"}})
			require.Empty(t, errs)
			find(t, fs, ResourceFile, "/amd", "amd-content")
			for _, v := range fs {
				require.NotEqual(t, "/arm", v.Attr(sources.AttrPath))
			}
			_, errs = collect(t, &Source{Layouts: []string{dir}, Platforms: []string{"linux/riscv64"}})
			require.Len(t, errs, 1)
			require.ErrorContains(t, errs[0], "no runtime image matches")
		})
	}
}

//nolint:exhaustruct // The fixture sets only the artifact and callback fields.
func TestLargeJSONArtifact(t *testing.T) {
	// A JSON artifact larger than the old 16 MiB cap must retain both raw and
	// decoded scanning, including escaped credentials after the large field.
	raw := `{"padding":"` + strings.Repeat("x", 17<<20) + `","token":"large\u002dmetadata\u002dsecret"}`
	jsonBytes, decodedSecret := 0, false
	r := &session{s: &Source{}, yield: func(f sources.Fragment, err error) error {
		require.NoError(t, err)
		if f.Attr(AttrRepresentation) == "json" {
			jsonBytes += len(f.Raw)
		}
		if f.Attr(AttrRepresentation) == "decoded" && strings.Contains(f.Raw, "large-metadata-secret") {
			decodedSecret = true
		}
		return nil
	}}
	layer := layerInput{
		descriptor: v1.Descriptor{Digest: sum([]byte(raw)), Size: int64(len(raw)), MediaType: "application/json"},
		open:       func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(raw)), nil },
	}
	require.NoError(t, r.layer(t.Context(), layer, map[string]string{}, newOverlay()))
	require.Equal(t, len(raw), jsonBytes)
	require.True(t, decodedSecret)
	require.ErrorContains(t, r.metadata(t.Context(), make([]byte, maxMetadataSize+1), "@config", ResourceConfig, nil), "metadata exceeds 64 MiB limit")
}

func TestDecodedMetadataLimitAndCancellation(t *testing.T) {
	raw := jsonBytes(t, map[string]any{strings.Repeat("k", 32<<10): make([]int, maxMetadataSize/(32<<10)+1), "escape": "\n"})
	decodedBytes := 0
	r := &session{s: &Source{}, yield: func(f sources.Fragment, err error) error {
		require.NoError(t, err)
		if f.Attr(AttrRepresentation) == "decoded" {
			decodedBytes += len(f.Raw)
		}
		return nil
	}}
	require.ErrorContains(t, r.metadata(t.Context(), raw, "@config", ResourceConfig, nil), "decoded metadata exceeds")
	require.Zero(t, decodedBytes)
	ctx, cancel := context.WithCancel(t.Context())
	r.yield = func(f sources.Fragment, err error) error { cancel(); return nil }
	require.ErrorIs(t, r.metadata(ctx, []byte(`{"value":"escaped\nvalue"}`), "@config", ResourceConfig, nil), context.Canceled)
}

// Go's tar.Writer cannot write GNU sparse entries. Start with its GNU header,
// then encode one data extent after a hole and recalculate the tar checksum.
func sparseLayer(t *testing.T, content string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	require.NoError(t, w.WriteHeader(&tar.Header{Name: "sparse", Mode: 0600, Size: int64(len(content)), Format: tar.FormatGNU}))
	_, err := w.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	data := b.Bytes()
	data[156] = tar.TypeGNUSparse
	copy(data[386:398], fmt.Sprintf("%011o\x00", 32))
	copy(data[398:410], fmt.Sprintf("%011o\x00", len(content)))
	copy(data[483:495], fmt.Sprintf("%011o\x00", 32+len(content)))
	for i := 148; i < 156; i++ {
		data[i] = ' '
	}
	sum := 0
	for _, v := range data[:512] {
		sum += int(v)
	}
	copy(data[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return data
}

func TestGNUSparseLayerContentsAndSizeLimit(t *testing.T) {
	const secret = "SPARSE_TEST_SECRET_abc123"
	data := sparseLayer(t, secret)
	tr := tar.NewReader(bytes.NewReader(data))
	h, err := tr.Next()
	require.NoError(t, err)
	require.Equal(t, byte(tar.TypeGNUSparse), h.Typeflag)
	expanded, err := io.ReadAll(tr)
	require.NoError(t, err)
	require.Equal(t, strings.Repeat("\x00", 32)+secret, string(expanded))
	f := newFixture(t)
	f.setIndex(f.image("amd64", [][]byte{data}, "gzip"))
	dir := f.directory()
	fs, errs := collect(t, &Source{Layouts: []string{dir}, MaxArchiveDepth: 8})
	require.Empty(t, errs)
	find(t, fs, ResourceFile, "/sparse", secret)
	_, errs = collect(t, &Source{Layouts: []string{dir}, MaxFileSize: int64(len(secret))})
	require.NotEmpty(t, errs)
	require.ErrorContains(t, errs[0], "max-file-size")
}

func TestNestedCompressionTrailerValidation(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(fmt.Sprintf("broken=%v", broken), func(t *testing.T) {
			data := gzipBytes(t, tarBytes(t, tarEntry{name: "token.txt", content: "NESTED_TEST_SECRET_abc123"}))
			if broken {
				data[len(data)-8] ^= 0xff
			}
			f := newFixture(t)
			f.setIndex(f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "bundle.tar.gz", content: string(data)}, tarEntry{name: "after", content: "still-scanned"})}, "tar"))
			fs, errs := collect(t, &Source{Layouts: []string{f.directory()}, MaxArchiveDepth: 8})
			if broken {
				require.NotEmpty(t, errs)
			} else {
				require.Empty(t, errs)
			}
			find(t, fs, ResourceFile, "/bundle.tar.gz!token.txt", "NESTED_TEST_SECRET_abc123")
			find(t, fs, ResourceFile, "/after", "still-scanned")
		})
	}
}

func TestDaemonFailureDiagnostic(t *testing.T) {
	for _, daemon := range []string{"docker", "podman"} {
		t.Run(daemon, func(t *testing.T) {
			transport := progressTransport(func(req *http.Request) (*http.Response, error) {
				//nolint:exhaustruct // Unspecified fixture fields intentionally use zero values.
				return &http.Response{StatusCode: 404, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"message":"No such image: review:missing https://user:password@example.test/image?token=secret"}`)), Request: req}, nil
			})
			//nolint:exhaustruct // Unspecified fixture fields intentionally use zero values.
			_, errs := collect(t, &Source{Images: []string{"review:missing"}, Daemon: daemon, DaemonHost: "http://engine.test", DaemonTransport: transport})
			require.Len(t, errs, 1)
			require.ErrorContains(t, errs[0], daemon+" image export: HTTP 404")
			require.ErrorContains(t, errs[0], "No such image: review:missing")
			require.NotContains(t, errs[0].Error(), "password")
			require.NotContains(t, errs[0].Error(), "token=secret")
		})
	}
}

func TestDaemonDiagnosticBound(t *testing.T) {
	reader := strings.NewReader(strings.Repeat("x", 30<<10))
	err := daemonResponseError(reader)
	require.Len(t, err.Error(), (16<<10)+len(" [truncated]"))
	require.True(t, strings.HasSuffix(err.Error(), "[truncated]"))
	require.Equal(t, (30<<10)-(16<<10)-1, reader.Len())
}

// A reader may legally return data and EOF together. Verification failures
// must remain visible even if a tar parser uses that data and ignores its error.
type eofWithData struct{ *bytes.Reader }

func (r eofWithData) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if r.Len() == 0 {
		err = io.EOF
	}
	return n, err
}

func TestDigestErrorSurvivesFinalDataRead(t *testing.T) {
	reader, err := verifyingReader(eofWithData{bytes.NewReader([]byte("wrong"))}, sum([]byte("right")))
	require.NoError(t, err)
	p := make([]byte, 5)
	_, err = io.ReadFull(reader, p)
	require.NoError(t, err) // io.ReadFull intentionally discards errors with a full buffer.
	_, err = io.Copy(io.Discard, reader)
	require.ErrorContains(t, err, "digest mismatch")
}

func TestOuterArchiveExpandedStreamLimit(t *testing.T) {
	f := newFixture(t)
	f.setIndex(f.image("amd64", nil, "tar"))
	archive := f.archive()
	limit := int64(len(archive))
	for _, encoded := range []bool{false, true} {
		for _, tail := range []int{0, 1, 1 << 20} {
			t.Run(fmt.Sprintf("compressed=%v/tail=%d", encoded, tail), func(t *testing.T) {
				data := append(bytes.Clone(archive), make([]byte, tail)...)
				if encoded {
					data = gzipBytes(t, data)
				}
				file := filepath.Join(t.TempDir(), "image.tar")
				require.NoError(t, os.WriteFile(file, data, 0600))
				_, errs := collect(t, &Source{Archives: []string{file}, MaxArchiveSize: limit})
				if tail == 0 {
					require.Empty(t, errs)
				} else {
					require.NotEmpty(t, errs)
					require.ErrorContains(t, errs[0], "max-archive-size")
				}
			})
		}
	}
	// Header/padding bytes count even when all payloads fit below the limit.
	file := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, os.WriteFile(file, archive, 0600))
	_, errs := collect(t, &Source{Archives: []string{file}, MaxArchiveSize: limit - 1})
	require.NotEmpty(t, errs)
	require.ErrorContains(t, errs[0], "max-archive-size")
}

//nolint:exhaustruct // Fixtures set only the fields relevant to each scenario.
func TestOuterArchiveTailValidation(t *testing.T) {
	f := newFixture(t)
	f.setIndex(f.image("amd64", nil, "tar"))
	archive := f.archive()
	for _, compressed := range []bool{false, true} {
		for _, failure := range []bool{false, true} {
			t.Run(fmt.Sprintf("compressed=%v/export-error=%v", compressed, failure), func(t *testing.T) {
				// Valid tar record padding is accepted. An engine error after the
				// padding must make even an HTTP 200 export fail without echoing it.
				data := append(bytes.Clone(archive), make([]byte, 10240)...)
				if failure {
					data = append(data, []byte(`{"error":"export failed: sensitive-value"}`)...)
				}
				if compressed {
					data = gzipBytes(t, data)
				}
				transport := progressTransport(func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(data)), Request: req}, nil
				})
				_, errs := collect(t, &Source{Images: []string{"app"}, Daemon: "docker", DaemonHost: "http://engine.test", DaemonTransport: transport})
				if failure {
					require.Len(t, errs, 1)
					require.ErrorContains(t, errs[0], "nonzero data after tar end marker")
					require.NotContains(t, errs[0].Error(), "sensitive-value")
				} else {
					require.Empty(t, errs)
				}
			})
		}
	}
}

func TestReadConfigFile(t *testing.T) {
	dir := t.TempDir()
	_, err := readConfigFile(t.Context(), dir)
	require.ErrorContains(t, err, "regular file")
	file := filepath.Join(dir, "config.json")
	require.NoError(t, os.WriteFile(file, []byte(`{}`), 0600))
	data, err := readConfigFile(t.Context(), file)
	require.NoError(t, err)
	require.Equal(t, `{}`, string(data))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = readConfigFile(ctx, file)
	require.ErrorIs(t, err, context.Canceled)
}

type zeroStream struct{ reads int64 }

func (r *zeroStream) Read(p []byte) (int, error) {
	clear(p)
	r.reads += int64(len(p))
	return len(p), nil
}

func TestLayerTailBoundAndValidation(t *testing.T) {
	endless := &zeroStream{}
	require.ErrorContains(t, drainLayerTail(t.Context(), endless), "padding exceeds")
	require.Equal(t, int64(maxLayerPadding+1), endless.reads)
	require.NoError(t, drainLayerTail(t.Context(), bytes.NewReader(make([]byte, maxLayerPadding))))
	require.ErrorContains(t, drainLayerTail(t.Context(), strings.NewReader("trailing-data")), "nonzero data")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, drainLayerTail(ctx, endless), context.Canceled)
}

func TestLayerTailFailuresPreserveOtherLayers(t *testing.T) {
	for _, tail := range [][]byte{[]byte("hidden trailing data"), make([]byte, maxLayerPadding+1)} {
		f := newFixture(t)
		lower := tarBytes(t, tarEntry{name: "lower", content: "lower-secret"})
		upper := append(tarBytes(t, tarEntry{name: "upper", content: "upper-secret"}), tail...)
		f.setIndex(f.image("amd64", [][]byte{lower, upper}, "gzip"))
		fs, errs := collect(t, &Source{Layouts: []string{f.directory()}, MaxArchiveDepth: 8})
		require.NotEmpty(t, errs)
		find(t, fs, ResourceFile, "/upper", "upper-secret")
		require.Equal(t, "unknown", find(t, fs, ResourceFile, "/lower", "lower-secret").Attr(AttrPathState))
	}
}

func TestLayerTrackingBudgetSpansLayers(t *testing.T) {
	r := &session{s: &Source{}, yield: func(sources.Fragment, error) error { return nil }}
	run := func(state *overlay, entries ...tarEntry) error {
		data := tarBytes(t, entries...)
		return r.layer(t.Context(), layerInput{
			descriptor: v1.Descriptor{MediaType: types.OCIUncompressedLayer},
			diffID:     sum(data),
			open:       func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil },
		}, map[string]string{AttrLayerIndex: "0"}, state)
	}
	state := newOverlay()
	state.budget.entries = maxImageLayerEntries - 2
	require.NoError(t, run(state, tarEntry{name: "dir", kind: tar.TypeDir}, tarEntry{name: "empty"}))
	require.ErrorContains(t, run(state, tarEntry{name: ".wh.deleted"}), "one million entries")
	state = newOverlay()
	state.budget.pathBytes = maxImagePathBytes - len("/a")
	require.NoError(t, run(state, tarEntry{name: "a"}))
	require.ErrorContains(t, run(state, tarEntry{name: "b"}), "paths exceed 64 MiB")
	// Filtering must not bypass accounting for the names retained by the overlay.
	state = newOverlay()
	state.budget.entries = maxImageLayerEntries
	r.s.Prefilter = func(map[string]string) bool { return true }
	require.ErrorContains(t, run(state, tarEntry{name: "excluded"}), "one million entries")
}

func TestHistoricalOccurrenceUsesFirstHidingLayer(t *testing.T) {
	f := newFixture(t)
	layers := [][]byte{
		tarBytes(t, tarEntry{name: "token", content: "old-secret"}, tarEntry{name: "dir/child", content: "child-old"}),
		tarBytes(t, tarEntry{name: ".wh.token"}, tarEntry{name: "dir/child", content: "child-new"}),
		tarBytes(t, tarEntry{name: "token", content: "new-secret"}, tarEntry{name: ".wh.dir"}),
	}
	f.setIndex(f.image("amd64", layers, "tar"))
	fs, errs := collect(t, &Source{Layouts: []string{f.directory()}})
	require.Empty(t, errs)
	old := find(t, fs, ResourceFile, "/token", "old-secret")
	require.Equal(t, "deleted", old.Attr(AttrPathState))
	require.Equal(t, sum(layers[1]).String(), old.Attr(AttrHiddenByLayer))
	require.Equal(t, "visible", find(t, fs, ResourceFile, "/token", "new-secret").Attr(AttrPathState))
	child := find(t, fs, ResourceFile, "/dir/child", "child-old")
	require.Equal(t, "overwritten", child.Attr(AttrPathState))
	require.Equal(t, sum(layers[1]).String(), child.Attr(AttrHiddenByLayer))
	child = find(t, fs, ResourceFile, "/dir/child", "child-new")
	require.Equal(t, "deleted", child.Attr(AttrPathState))
	require.Equal(t, sum(layers[2]).String(), child.Attr(AttrHiddenByLayer))
}

func TestWhiteoutBeforeSameLayerReplacement(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		f := newFixture(t)
		entries := []tarEntry{{name: ".wh.token"}, {name: "token", content: "new-secret"}}
		if reverse {
			entries[0], entries[1] = entries[1], entries[0]
		}
		f.setIndex(f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "token", content: "old-secret"}), tarBytes(t, entries...)}, "tar"))
		fs, errs := collect(t, &Source{Layouts: []string{f.directory()}})
		require.Empty(t, errs)
		require.Equal(t, "deleted", find(t, fs, ResourceFile, "/token", "old-secret").Attr(AttrPathState))
		require.Equal(t, "visible", find(t, fs, ResourceFile, "/token", "new-secret").Attr(AttrPathState))
	}
}

//nolint:exhaustruct // Fixtures set only the fields relevant to each scenario.
func TestDaemonReferenceIsOneLiteralName(t *testing.T) {
	f := newFixture(t)
	f.setIndex(f.image("amd64", nil, "tar"))
	for _, ref := range []string{"registry.test/team/app:local", "app@sha256:abcd", "../get?names=other#fragment", "app:local; $(touch marker)", "app:one,other:two"} {
		t.Run(ref, func(t *testing.T) {
			var requests int
			transport := progressTransport(func(req *http.Request) (*http.Response, error) {
				requests++
				require.Equal(t, "engine.test", req.URL.Host)
				require.Equal(t, http.MethodGet, req.Method)
				require.Equal(t, "/images/"+url.PathEscape(ref)+"/get", req.URL.EscapedPath())
				require.Empty(t, req.URL.RawQuery)
				require.Empty(t, req.URL.Fragment)
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(f.archive())), Request: req}, nil
			})
			_, errs := collect(t, &Source{Images: []string{ref}, Daemon: "docker", DaemonHost: "http://engine.test", DaemonTransport: transport})
			require.Empty(t, errs)
			require.Equal(t, 1, requests)
		})
	}
}

//nolint:exhaustruct // Fixtures set only the fields relevant to each scenario.
func TestInvalidLayerEntries(t *testing.T) {
	for _, entry := range []tarEntry{
		{name: "unknown", kind: 'Z'},
		{name: "dir/.wh.."},
		{name: "dir/.wh..."},
	} {
		t.Run(entry.name, func(t *testing.T) {
			f := newFixture(t)
			lower := tarBytes(t, tarEntry{name: "file", content: "lower-secret"})
			f.setIndex(f.image("amd64", [][]byte{lower, tarBytes(t, entry)}, "tar"))
			fs, errs := collect(t, &Source{Layouts: []string{f.directory()}})
			require.NotEmpty(t, errs)
			found := find(t, fs, ResourceFile, "/file", "lower-secret")
			require.Equal(t, "unknown", found.Attr(AttrPathState))
		})
	}
}

//nolint:exhaustruct // Fixtures set only the fields relevant to each scenario.
func TestGlobalPAXHeaderDoesNotHideFile(t *testing.T) {
	for _, sameLayerFile := range []bool{false, true} {
		t.Run(fmt.Sprint(sameLayerFile), func(t *testing.T) {
			f := newFixture(t)
			lower := tarBytes(t, tarEntry{name: "file", content: "lower-secret"})
			entries := []tarEntry{{name: "file", kind: tar.TypeXGlobalHeader, pax: map[string]string{"comment": "global-secret"}}}
			want := "visible"
			if sameLayerFile {
				entries = append(entries, tarEntry{name: "file", content: "upper-secret"})
				want = "overwritten"
			}
			f.setIndex(f.image("amd64", [][]byte{lower, tarBytes(t, entries...)}, "tar"))
			fs, errs := collect(t, &Source{Layouts: []string{f.directory()}})
			require.Empty(t, errs)
			found := find(t, fs, ResourceFile, "/file", "lower-secret")
			require.Equal(t, want, found.Attr(AttrPathState))
			find(t, fs, ResourceLayerMetadata, "/file", "global-secret")
			if sameLayerFile {
				find(t, fs, ResourceFile, "/file", "upper-secret")
			}
		})
	}
}

//nolint:exhaustruct // Fixtures set only the fields relevant to each scenario.
func TestXZDictionaryLimitAndIntegrity(t *testing.T) {
	f := newFixture(t)
	f.setIndex(f.image("amd64", nil, "tar"))
	var encoded bytes.Buffer
	w, err := xz.NewWriter(&encoded)
	require.NoError(t, err)
	_, err = w.Write(f.archive())
	require.NoError(t, err)
	require.NoError(t, w.Close())
	for _, mode := range []string{"valid", "dictionary", "truncated", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			data := bytes.Clone(encoded.Bytes())
			switch mode {
			case "dictionary":
				// Change only the block's LZMA2 property and its header CRC.
				// A tiny stream must not be allowed to request a 4 GiB dictionary.
				header := data[12 : 12+(int(data[12])+1)*4]
				require.Equal(t, []byte{0, 0x21, 1}, header[1:4])
				header[4] = 40
				binary.LittleEndian.PutUint32(header[len(header)-4:], crc32.ChecksumIEEE(header[:len(header)-4]))
			case "truncated":
				data = data[:len(data)-5]
			case "trailing":
				data = append(data, []byte("unexpected trailing data")...)
			}
			file := filepath.Join(t.TempDir(), "image.tar.xz")
			require.NoError(t, os.WriteFile(file, data, 0600))
			_, errs := collect(t, &Source{Archives: []string{file}})
			if mode == "valid" {
				require.Empty(t, errs)
			} else {
				require.NotEmpty(t, errs)
				if mode == "dictionary" {
					require.Contains(t, fmt.Sprint(errs), "dictionary size exceeds max")
				}
			}
		})
	}
}

//nolint:exhaustruct // Fixtures set only the fields relevant to each scenario.
func TestRepeatedIndexWorkLimit(t *testing.T) {
	f := newFixture(t)
	d := f.image("amd64", nil, "tar")
	// Only five stored manifests, but 11,111 occurrences if walked naively.
	for range 4 {
		children := make([]v1.Descriptor, 10)
		for i := range children {
			children[i] = d
		}
		d = f.blob(jsonBytes(t, v1.IndexManifest{SchemaVersion: 2, Manifests: children}), types.OCIImageIndex)
	}
	f.index = f.blobs[d.Digest.String()]
	good := newFixture(t)
	good.setIndex(good.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "file", content: "next-target-secret"})}, "tar"))
	fs, errs := collect(t, &Source{Layouts: []string{f.directory(), good.directory()}, Prefilter: func(attrs map[string]string) bool {
		return attrs[sources.AttrResource] != ResourceFile
	}})
	require.Len(t, errs, 1)
	require.ErrorIs(t, errs[0], errManifestVisits)
	find(t, fs, ResourceFile, "/file", "next-target-secret")
}

//nolint:exhaustruct // Fixtures set only the fields relevant to each scenario.
func TestFailedManifestWorkLimit(t *testing.T) {
	for _, count := range []int{maxManifestVisits - 1, maxManifestVisits} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			missing := v1.Descriptor{Digest: sum([]byte("missing")), Size: 2, MediaType: types.OCIManifestSchema1}
			children := make([]v1.Descriptor, count)
			for i := range children {
				children[i] = missing
			}
			raw := jsonBytes(t, v1.IndexManifest{SchemaVersion: 2, Manifests: children})
			fetches, failures := 0, 0
			missingErr := errors.New("missing manifest")
			store := imageStore{manifest: func(v1.Descriptor) ([]byte, error) {
				fetches++
				return nil, missingErr
			}}
			r := &session{s: &Source{}, yield: func(_ sources.Fragment, err error) error {
				if err != nil {
					require.ErrorIs(t, err, missingErr)
					failures++
				}
				return nil
			}}
			err := r.walk(t.Context(), store, raw, v1.Descriptor{Digest: sum(raw), Size: int64(len(raw)), MediaType: types.OCIImageIndex}, map[string]string{}, 0)
			if count < maxManifestVisits {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, errManifestVisits)
			}
			require.Equal(t, maxManifestVisits-1, fetches, "the root consumes one visit; the next child must not be fetched")
			require.Equal(t, fetches, failures)
			require.Equal(t, maxManifestVisits, r.manifestVisits)
		})
	}
}
