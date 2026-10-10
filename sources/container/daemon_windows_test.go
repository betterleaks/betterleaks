package container

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/stretchr/testify/require"
)

//nolint:exhaustruct // Fixtures set only fields relevant to pipe export and cancellation.
func TestDaemonNamedPipe(t *testing.T) {
	name := fmt.Sprintf("betterleaks-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	pipe := `\\.\pipe\` + name
	listener, err := winio.ListenPipe(pipe, nil)
	require.NoError(t, err)
	f := newFixture(t)
	f.setIndex(f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "file", content: "pipe-secret"})}, "tar"))
	data := f.archive()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "GET" || req.URL.Path != "/images/team/app:local/get" {
			http.Error(w, "unexpected request", 400)
			return
		}
		_, _ = w.Write(data)
	})}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Close(); <-done })
	t.Setenv("PATH", t.TempDir())
	fragments, errs := collect(t, &Source{Images: []string{"team/app:local"}, Daemon: "docker", DaemonHost: "npipe:////./pipe/" + name})
	require.Empty(t, errs)
	find(t, fragments, ResourceFile, "/file", "pipe-secret")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = dialDaemonPipe(ctx, pipe+"-missing")
	require.ErrorIs(t, err, context.Canceled)
}
