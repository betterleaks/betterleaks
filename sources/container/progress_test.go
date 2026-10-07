package container

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/sources"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestContainerArchiveWarningsIncludeLayerContext(t *testing.T) {
	var archive bytes.Buffer
	w := zip.NewWriter(&archive)
	member, err := w.CreateHeader(&zip.FileHeader{Name: "broken.class", Method: zip.Store})
	require.NoError(t, err)
	_, err = io.WriteString(member, "private-archive-content")
	require.NoError(t, err)
	require.NoError(t, w.Close())
	data := archive.Bytes()
	index := bytes.Index(data, []byte("private-archive-content"))
	require.NotEqual(t, -1, index)
	data[index] ^= 1 // Preserve ZIP structure but invalidate the member's CRC.

	f := newFixture(t)
	layer := tarBytes(t, tarEntry{name: "lib/broken.jar", content: string(data)}, tarEntry{name: "after", content: "still-scanned"})
	d := f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "base", content: "base"}), layer}, "gzip")
	var manifest v1.Manifest
	require.NoError(t, json.Unmarshal(f.blobs[d.Digest.String()], &manifest))
	f.setIndex(d)
	dir := f.directory()
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.WarnLevel)
	fs, errs := collect(t, &Source{Layouts: []string{dir}, MaxArchiveDepth: 8, Logger: &logger})
	require.NotEmpty(t, errs)
	find(t, fs, ResourceFile, "/after", "still-scanned")
	var warning map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &warning))
	require.Equal(t, "could not read archive content", warning["message"])
	require.Contains(t, warning["error"], "checksum error")
	require.Equal(t, "/lib/broken.jar!broken.class", warning["path"])
	require.NotEmpty(t, warning["image"])
	require.Equal(t, "linux/amd64", warning["platform"])
	require.Equal(t, "1", warning["layer_index"])
	require.Equal(t, manifest.Layers[1].Digest.String(), warning["layer_digest"])
	require.Equal(t, sum(layer).String(), warning["diff_id"])
	require.NotContains(t, logs.String(), "archive-content")
}

type progressLogBuffer struct {
	sync.Mutex
	bytes.Buffer
}

func (b *progressLogBuffer) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.Buffer.Write(p)
}

func (b *progressLogBuffer) snapshot() string {
	b.Lock()
	defer b.Unlock()
	return b.Buffer.String()
}

func TestProgressContinuesDuringBlockedReadAndStopsOnFinish(t *testing.T) {
	var logs progressLogBuffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	p := newProgress(t.Context(), &logger, time.Millisecond, "container layer scan", "layer_index", 3)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	p.setPhase("reading and scanning")
	tracked := p.reader(reader)
	readDone := make(chan error, 1)
	go func() { _, err := io.Copy(io.Discard, tracked); readDone <- err }()
	require.Eventually(t, func() bool { return strings.Contains(logs.snapshot(), `"message":"container layer scan progress"`) }, time.Second, time.Millisecond)
	require.Contains(t, logs.snapshot(), `"bytes_read":0`)
	_, err := writer.Write([]byte("content-must-not-appear-in-logs"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	require.NoError(t, <-readDone)
	p.file()
	p.finish(nil)
	select {
	case <-p.stopped:
	default:
		t.Fatal("progress goroutine still running")
	}
	output := logs.snapshot()
	require.NotContains(t, output, "content-must-not-appear-in-logs")
	lines := strings.Split(strings.TrimSpace(output), "\n")
	last := lines[len(lines)-1]
	require.Contains(t, last, `"message":"container layer scan finished"`)
	require.Contains(t, last, `"bytes_read":31`)
	require.Contains(t, last, `"files_enumerated":1`)
	require.Contains(t, last, `"failed":false`)
}

func TestContainerDebugLogs(t *testing.T) {
	f := newFixture(t)
	f.setIndex(f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "app.env", content: "file-secret"})}, "gzip"), f.image("arm64", nil, "tar"))
	dir := f.directory()
	for _, level := range []zerolog.Level{zerolog.DebugLevel, zerolog.InfoLevel} {
		var logs bytes.Buffer
		logger := zerolog.New(&logs).Level(level)
		_, errs := collect(t, &Source{Layouts: []string{dir}, Platforms: []string{"linux/amd64"}, Logger: &logger})
		require.Empty(t, errs)
		output := logs.String()
		if level == zerolog.InfoLevel {
			require.NotContains(t, output, `"level":"debug"`)
			continue
		}
		for _, message := range []string{"opening OCI image layout", "enumerating container index", "selected container manifest", "skipping container platform", "container config read started", "scanning container image", "scanning container metadata", "container layer scan started", "container layer scan finished"} {
			require.Contains(t, output, message)
		}
		for _, secret := range []string{"file-secret", "history-secret", "config-secret", "label-secret"} {
			require.NotContains(t, output, secret)
		}
		require.Contains(t, output, `"platform":"linux/amd64"`)
		require.Contains(t, output, `"files_enumerated":1`)
	}
}

func TestProgressDisabledAndErrorLogging(t *testing.T) {
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.InfoLevel)
	for _, logger := range []*zerolog.Logger{nil, &logger} {
		p := newProgress(t.Context(), logger, time.Second, "test")
		require.Nil(t, p)
		input := strings.NewReader("content")
		require.Same(t, input, p.reader(input))
		p.file()
		p.setPhase("reading")
		p.finish(nil)
	}
	logger = zerolog.New(&logs).Level(zerolog.DebugLevel)
	p := newProgress(t.Context(), &logger, time.Hour, "test")
	p.finish(errors.New("response-body-secret"))
	require.Contains(t, logs.String(), `"failed":true`)
	require.NotContains(t, logs.String(), "response-body-secret")
}

type progressTransport func(*http.Request) (*http.Response, error)

func (f progressTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestContainerRegistryDebugLogging(t *testing.T) {
	f := newFixture(t)
	f.setIndex(f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "file", content: "private-file-content"})}, "gzip"))
	transport := progressTransport(func(req *http.Request) (*http.Response, error) {
		data := []byte("{}")
		mediaType := "application/json"
		if strings.HasSuffix(req.URL.Path, "/manifests/latest") {
			data = f.index
			mediaType = "application/vnd.oci.image.index.v1+json"
		} else if req.URL.Path != "/v2/" {
			key := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
			data = f.blobs[key]
			if strings.Contains(req.URL.Path, "/manifests/") {
				mediaType = "application/vnd.oci.image.manifest.v1+json"
			}
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{mediaType}}, Body: io.NopCloser(bytes.NewReader(data)), ContentLength: int64(len(data)), Request: req}, nil
	})
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	_, errs := collect(t, &Source{Images: []string{"registry.example.test/app:latest"}, Anonymous: true, Transport: transport, Logger: &logger})
	require.Empty(t, errs)
	output := logs.String()
	for _, message := range []string{"container image resolution started", "container image resolution finished", "resolved container image", "container manifest fetch started", "container manifest fetch finished", "container layer scan started", "container layer scan finished"} {
		require.Contains(t, output, message)
	}
	require.NotContains(t, output, "private-file-content")
	require.Contains(t, output, `"image":"registry.example.test/app:latest"`)
}

func TestContainerScannedBytesRespectPrefilter(t *testing.T) {
	cfg, err := config.Default()
	require.NoError(t, err)
	skip := detect.NewDetector(cfg).SkipFunc()
	f := newFixture(t)
	pythonContent := strings.Repeat("python package data\n", 100_000)
	appContent := "application content\n"
	f.setIndex(f.image("amd64", [][]byte{tarBytes(t,
		tarEntry{name: "usr/local/lib/python3.12/site-packages/example/data", content: pythonContent},
		tarEntry{name: "app/readme.txt", content: appContent},
	)}, "gzip"))
	dir := f.directory()
	for _, filtered := range []bool{true, false} {
		name := "unfiltered"
		if filtered {
			name = "default prefilter"
		}
		t.Run(name, func(t *testing.T) {
			src := &Source{Layouts: []string{dir}}
			wantContent := len(appContent)
			if filtered {
				src.Prefilter = skip
			} else {
				wantContent += len(pythonContent)
			}
			fragments, errs := collect(t, src)
			require.Empty(t, errs)
			var expectedScan, actualContent uint64
			for _, fragment := range fragments {
				expectedScan += uint64(len(fragment.Raw))
				if fragment.Attr(sources.AttrResource) == ResourceFile {
					actualContent += uint64(len(fragment.Raw))
				}
			}
			require.Equal(t, uint64(wantContent), actualContent)
			scanner := detect.NewDetector(&config.Config{})
			for result := range scanner.Run(t.Context(), src) {
				require.NoError(t, result.Err)
			}
			require.Equal(t, expectedScan, scanner.TotalBytes.Load())
			if filtered {
				require.Less(t, scanner.TotalBytes.Load(), uint64(4096))
			} else {
				require.Greater(t, scanner.TotalBytes.Load(), uint64(len(pythonContent)))
			}
		})
	}
}
