package scm

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// BenchmarkClonePack sends the same existing SHA-1 pack over loopback HTTP to
// each implementation. This measures transport, streaming validation, indexing,
// and publication without public-server or network variability. HEAD must name
// a commit present in the supplied pack. The benchmark is baseline-compatible.
func BenchmarkClonePack(b *testing.B) {
	pack, head := os.Getenv("BETTERLEAKS_BENCH_PACK"), os.Getenv("BETTERLEAKS_BENCH_HEAD")
	if pack == "" || head == "" {
		b.Skip("set BETTERLEAKS_BENCH_PACK and BETTERLEAKS_BENCH_HEAD")
	}
	info, err := os.Stat(pack)
	require.NoError(b, err)
	require.Len(b, head, 40)
	packet := func(w io.Writer, text string) { _, _ = fmt.Fprintf(w, "%04x%s", len(text)+4, text) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/info/refs"):
			w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
			packet(w, "# service=git-upload-pack\n")
			_, _ = io.WriteString(w, "0000")
			packet(w, head+" HEAD\x00symref=HEAD:refs/heads/main ofs-delta no-progress\n")
			packet(w, head+" refs/heads/main\n")
			_, _ = io.WriteString(w, "0000")
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git-upload-pack"):
			_, _ = io.Copy(io.Discard, r.Body)
			file, err := os.Open(pack)
			if err != nil {
				b.Error(err)
				http.Error(w, "pack unavailable", http.StatusInternalServerError)
				return
			}
			defer file.Close()
			w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
			packet(w, "NAK\n")
			if _, err := io.Copy(w, file); err != nil {
				b.Error(err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	b.ReportAllocs()
	b.SetBytes(info.Size())
	for b.Loop() {
		dest := filepath.Join(b.TempDir(), "clone")
		require.NoError(b, CloneAuthed(b.Context(), server.URL+"/repo.git", "", dest, CloneOptions{Refs: nil, AllRefs: false}))
		headFile, err := os.ReadFile(filepath.Join(dest, "HEAD"))
		require.NoError(b, err)
		require.Equal(b, "ref: refs/heads/main\n", string(headFile))
		require.NoError(b, os.RemoveAll(dest))
	}
}
