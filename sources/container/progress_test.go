package container

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/prefilter"
	"github.com/stretchr/testify/require"
)

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
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	p := newProgress(t.Context(), logger, time.Millisecond, "container layer scan", "layer_index", 3)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	p.setPhase("reading and scanning")
	tracked := p.reader(reader)
	readDone := make(chan error, 1)
	go func() { _, err := io.Copy(io.Discard, tracked); readDone <- err }()
	require.Eventually(t, func() bool { return strings.Contains(logs.snapshot(), `"msg":"container layer scan progress"`) }, time.Second, time.Millisecond)
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
	require.Contains(t, last, `"msg":"container layer scan finished"`)
	require.Contains(t, last, `"bytes_read":31`)
	require.Contains(t, last, `"files_enumerated":1`)
	require.Contains(t, last, `"failed":false`)
}

func TestContainerDebugLogs(t *testing.T) {
	f := newFixture(t)
	f.setIndex(f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "app.env", content: "file-secret"})}, "gzip"), f.image("arm64", nil, "tar"))
	dir := f.directory()
	for _, level := range []slog.Level{slog.LevelDebug, slog.LevelInfo} {
		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: level}))
		_, errs := collect(t, &Source{Layouts: []string{dir}, Platforms: []string{"linux/amd64"}, Logger: logger})
		require.Empty(t, errs)
		output := logs.String()
		if level == slog.LevelInfo {
			require.NotContains(t, output, `"level":"DEBUG"`)
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
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	for _, logger := range []*slog.Logger{nil, logger} {
		p := newProgress(t.Context(), logger, time.Second, "test")
		require.Nil(t, p)
		input := strings.NewReader("content")
		require.Same(t, input, p.reader(input))
		p.file()
		p.setPhase("reading")
		p.finish(nil)
	}
	logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	p := newProgress(t.Context(), logger, time.Hour, "test")
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
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	_, errs := collect(t, &Source{Images: []string{"registry.example.test/app:latest"}, Anonymous: true, Transport: transport, Logger: logger})
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
	skip, err := prefilter.Compile(cfg.PrefilterExpr, prefilter.Options{})
	require.NoError(t, err)
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
			scanner, err := scan.New(&config.Config{})
			require.NoError(t, err)
			summary, err := scanner.Scan(t.Context(), src, nil)
			require.NoError(t, err)
			require.Equal(t, expectedScan, summary.BytesInspected)
			if filtered {
				require.Less(t, summary.BytesInspected, uint64(4096))
			} else {
				require.Greater(t, summary.BytesInspected, uint64(len(pythonContent)))
			}
		})
	}
}
