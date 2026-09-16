package sources

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestURLFragments(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	entry, err := zw.Create("secret.txt")
	require.NoError(t, err)
	_, err = io.WriteString(entry, "secret in an archive\n")
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		require.True(t, ok)
		require.Equal(t, "user", user)
		require.Equal(t, "password", pass)
		require.Equal(t, "private", r.URL.Query().Get("token"))
		if r.URL.Path == "/bundle.zip" {
			_, _ = w.Write(archive.Bytes())
		} else {
			_, _ = io.WriteString(w, "secret in plaintext\n")
		}
	}))
	defer srv.Close()
	for _, path := range []string{"/secret.txt", "/bundle.zip"} {
		t.Run(path, func(t *testing.T) {
			src := &URL{
				URL:             strings.Replace(srv.URL, "://", "://user:password@", 1) + path + "?token=private",
				MaxArchiveDepth: 1,
			}
			var fragments []Fragment
			err := src.Fragments(t.Context(), func(f Fragment, err error) error {
				require.NoError(t, err)
				fragments = append(fragments, f)
				return nil
			})
			require.NoError(t, err)
			require.Len(t, fragments, 1)
			require.Contains(t, fragments[0].Raw, "secret in")
			require.Equal(t, srv.URL+path, fragments[0].Attr(AttrURL))
			require.Equal(t, ResourceURLContent, fragments[0].Attr(AttrResource))
			if path == "/bundle.zip" {
				require.Equal(t, "bundle.zip!secret.txt", fragments[0].Attr(AttrPath))
			}
			stop := errors.New("stop scanning")
			require.ErrorIs(t, src.Fragments(t.Context(), func(Fragment, error) error { return stop }), stop)
			files, err := os.ReadDir(tmp)
			require.NoError(t, err)
			require.Empty(t, files)
		})
	}
	// Archive depth zero must not silently enable archive scanning.
	src := &URL{URL: strings.Replace(srv.URL, "://", "://user:password@", 1) + "/bundle.zip?token=private"}
	require.NoError(t, src.Fragments(t.Context(), func(Fragment, error) error { t.Fatal("archive should be skipped"); return nil }))
}

func TestURLArchiveContentDetectionAndFiltering(t *testing.T) {
	zipBytes := func(name string, content []byte) []byte {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		entry, err := zw.Create(name)
		require.NoError(t, err)
		_, err = entry.Write(content)
		require.NoError(t, err)
		require.NoError(t, zw.Close())
		return buf.Bytes()
	}
	secret := []byte("fixture-secret-value\n")
	archive := zipBytes("secret.txt", secret)
	nested := zipBytes("inner", archive)
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, err := gz.Write(secret)
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	for _, tc := range []struct {
		name string
		body []byte
		path string
	}{
		{"zip", archive, "download!secret.txt"},
		{"nested zip", nested, "download!inner!secret.txt"},
		{"gzip", compressed.Bytes(), "download"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/redirect" {
					http.Redirect(w, r, "/download", http.StatusFound)
					return
				}
				// Neither a filename nor an accurate MIME type is required.
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write(tc.body)
			}))
			defer srv.Close()
			for _, path := range []string{"/download", "/redirect"} {
				for _, skip := range []bool{false, true} {
					wantPath := strings.Replace(tc.path, "download", strings.TrimPrefix(path, "/"), 1)
					src := &URL{URL: srv.URL + path, MaxArchiveDepth: 2}
					src.ShouldSkip = func(attrs map[string]string) bool {
						return skip && attrs[AttrResource] == ResourceURLContent &&
							attrs[AttrURL] == src.URL && attrs[AttrPath] == wantPath
					}
					var fragments []Fragment
					require.NoError(t, src.Fragments(t.Context(), func(f Fragment, err error) error {
						fragments = append(fragments, f)
						return err
					}))
					if skip {
						require.Empty(t, fragments, "exclude using complete source and archive attributes")
					} else {
						require.Len(t, fragments, 1)
						require.Equal(t, string(secret), fragments[0].Raw)
						require.Equal(t, wantPath, fragments[0].Attr(AttrPath))
					}
				}
			}
			src := &URL{URL: srv.URL + "/download"}
			require.NoError(t, src.Fragments(t.Context(), func(Fragment, error) error {
				t.Fatal("content detection must respect archive depth zero")
				return nil
			}))
		})
	}
}

func TestURLSizeAndCancellation(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/chunked":
			w.(http.Flusher).Flush()
		case "/slow":
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		case "/error":
			w.WriteHeader(403)
			return
		}
		_, _ = io.WriteString(w, "1234567890")
	}))
	defer srv.Close()
	for _, path := range []string{"/length", "/chunked"} {
		for _, limit := range []int64{5, 10} {
			n := 0
			src := &URL{
				URL:     srv.URL + path,
				MaxSize: limit,
			}
			require.NoError(t, src.Fragments(t.Context(), func(Fragment, error) error { n++; return nil }))
			if limit == 5 {
				require.Zero(t, n, "do not scan truncated responses")
			} else {
				require.Equal(t, 1, n)
			}
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	err := (&URL{URL: srv.URL + "/slow"}).Fragments(ctx, func(Fragment, error) error { return nil })
	require.ErrorIs(t, err, context.DeadlineExceeded)
	err = (&URL{URL: srv.URL + "/error"}).Fragments(t.Context(), func(Fragment, error) error { t.Fatal("error response scanned"); return nil })
	require.ErrorContains(t, err, "403")
	files, err := os.ReadDir(tmp)
	require.NoError(t, err)
	require.Empty(t, files)
}

func TestURLSkipBeforeDownloadAndErrorRedaction(t *testing.T) {
	client := &http.Client{Transport: autoRoundTrip(func(*http.Request) (*http.Response, error) {
		return nil, context.Canceled
	})}
	src := &URL{
		URL:        "https://user:password@example.com/file?token=private",
		HTTPClient: client,
	}
	err := src.Fragments(t.Context(), func(Fragment, error) error { return nil })
	require.ErrorIs(t, err, context.Canceled)
	require.NotContains(t, err.Error(), "password")
	require.NotContains(t, err.Error(), "private")
	src.ShouldSkip = func(attrs map[string]string) bool { return attrs[AttrResource] == ResourceURLContent }
	require.NoError(t, src.Fragments(t.Context(), func(Fragment, error) error { t.Fatal("skipped URL scanned"); return nil }))
}
