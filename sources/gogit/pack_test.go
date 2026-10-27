//nolint:exhaustruct // Test fixtures specify only the fields relevant to each scenario.
package gogit

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/internal/gitobj"
	format "github.com/go-git/go-git/v5/plumbing/format/config"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/stretchr/testify/require"
)

type packBytes struct{ *bytes.Reader }

func (packBytes) Close() error { return nil }

func TestPackedObjectBounds(t *testing.T) {
	var compressed bytes.Buffer
	z := zlib.NewWriter(&compressed)
	_, err := z.Write([]byte("abc"))
	require.NoError(t, err)
	require.NoError(t, z.Close())
	good := append([]byte{0x33}, compressed.Bytes()...)
	for _, tc := range []struct {
		name  string
		data  []byte
		valid bool
	}{
		{"valid", good, true},
		{"invalid-type", []byte{0x50}, false},
		{"truncated-header", []byte{0xb0}, false},
		{"overflow", append([]byte{0xb0}, bytes.Repeat([]byte{0xff}, 10)...), false},
		{"invalid-zlib", []byte{0x33, 0, 0}, false},
		{"truncated-zlib", good[:len(good)-1], false},
		{"overrun", append([]byte{0x32}, compressed.Bytes()...), false},
		{"short-result", append([]byte{0x34}, compressed.Bytes()...), false},
		{"zero-delta-offset", []byte{0x60, 0}, false},
		{"delta-offset-before-header", []byte{0x60, 1}, false},
		{"truncated-reference", []byte{0x70, 1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := append(make([]byte, 12), tc.data...)
			p := &objectPack{file: packBytes{bytes.NewReader(data)}, end: int64(len(data)), hashSize: 20}
			s := &objectStorage{ctx: t.Context(), limit: 1024}
			e, err := s.inflate(p, 12, true)
			if !tc.valid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, gitobj.BlobObject, e.kind)
			require.Equal(t, "abc", e.raw)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			s.ctx = ctx
			_, err = s.inflate(p, 12, true)
			require.ErrorIs(t, err, context.Canceled)
		})
	}
}

func FuzzPackedObject(f *testing.F) {
	f.Add([]byte{0xb0, 0xff, 0xff})
	f.Add([]byte{0x60, 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 65536 {
			t.Skip()
		}
		data := append(make([]byte, 12), input...)
		p := &objectPack{file: packBytes{bytes.NewReader(data)}, end: int64(len(data)), hashSize: 20}
		s := &objectStorage{ctx: t.Context(), limit: 65536}
		e, err := s.inflate(p, 12, true)
		if err == nil {
			require.LessOrEqual(t, len(e.raw), 65536)
		}
	})
}

func TestPackedObjects(t *testing.T) {
	for _, objectFormat := range []format.ObjectFormat{format.SHA1, format.SHA256} {
		for _, offsets := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/offsets=%v", objectFormat, offsets), func(t *testing.T) {
				repo := t.TempDir()
				gitFixture(t, repo, "init", "-q", "--object-format="+string(objectFormat))
				gitFixture(t, repo, "config", "user.name", "Pack Test")
				gitFixture(t, repo, "config", "user.email", "pack@example.test")
				for revision := range 20 {
					var content strings.Builder
					for line := range 1000 {
						value := 0
						if line%37 == 0 {
							value = revision
						}
						fmt.Fprintf(&content, "line %04d with some shared content %d\n", line, value)
					}
					require.NoError(t, os.WriteFile(filepath.Join(repo, "data"), []byte(content.String()), 0600))
					gitFixture(t, repo, "add", "data")
					gitFixture(t, repo, "commit", "-qm", strconv.Itoa(revision))
				}
				args := []string{"-c", "pack.writeReverseIndex=true", "pack-objects", "--all", "--window=20", "--depth=20", ".git/objects/pack/pack"}
				if offsets {
					args = append(args, "--delta-base-offset")
				}
				gitFixture(t, repo, args...)
				r, cleanup, err := (&Source{RepoPath: repo, CacheMiB: 1}).open(t.Context())
				require.NoError(t, err)
				defer cleanup()
				store := r.Storer.(*objectStorage)
				require.Len(t, store.packs, 1)
				p := store.packs[0]
				iter, err := p.index.Entries()
				require.NoError(t, err)
				defer iter.Close()
				count, deltas := 0, 0
				for {
					e, err := iter.Next()
					if err == io.EOF {
						break
					}
					require.NoError(t, err)
					entry, err := store.inflate(p, int64(e.Offset), true)
					require.NoError(t, err)
					if entry.kind.IsDelta() {
						deltas++
						want := gitobj.REFDeltaObject
						if offsets {
							want = gitobj.OFSDeltaObject
						}
						require.Equal(t, want, entry.kind)
					}
					store.objects.Clear() // Exercise reconstruction, not an earlier cache hit.
					kind, err := store.ObjectType(e.Hash)
					require.NoError(t, err)
					o, err := store.read(e.Hash)
					require.NoError(t, err)
					require.Equal(t, o.Type(), kind)
					h := gitobj.NewHasher(objectFormat, o.Type(), o.Size())
					h.Write([]byte(o.raw))
					require.Equal(t, e.Hash, h.Sum())
					count++
				}
				require.Equal(t, 60, count)
				require.Greater(t, deltas, 10)
			})
		}
	}
}

func TestPackWithoutReverseIndex(t *testing.T) {
	repo := newHistory(t)
	gitFixture(t, repo, "-c", "pack.writeReverseIndex=false", "repack", "-ad")
	r, cleanup, err := (&Source{RepoPath: repo}).open(t.Context())
	require.NoError(t, err)
	require.Len(t, r.Storer.(*objectStorage).packs, 1, "packs without .rev use a compact reverse permutation")
	cleanup()
	t.Setenv("PATH", t.TempDir())
	fs := collect(t, &Source{RepoPath: repo})
	require.Equal(t, "file.txt:2", textOccurrences(fs)["TOKEN_CHANGED\n"])
}

func TestApplyDelta(t *testing.T) {
	for _, tc := range []struct {
		name, base, delta, want string
	}{
		{"copy-and-literal", "abc", "\x03\x04\x90\x03\x01d", "abcd"},
		{"empty-base", "", "\x00\x03\x03abc", "abc"},
		{"empty-result", "abc", "\x03\x00", ""},
		{"offset", "abcdef", "\x06\x03\x91\x02\x03", "cde"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := applyDelta(t.Context(), tc.base, tc.delta, 1<<20)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
	base := strings.Repeat("x", 65536)
	header := binary.AppendUvarint(nil, uint64(len(base)))
	header = binary.AppendUvarint(header, uint64(len(base)))
	header = append(header, 0x80)
	got, err := applyDelta(t.Context(), base, string(header), 1<<20)
	require.NoError(t, err)
	require.Equal(t, base, got)
	for _, delta := range []string{
		"", "\x80", "\x03", "\x04\x00", "\x03\x04\x04abc",
		"\x03\x01\x00", "\x03\x01\x01x\x01y", "\x03\x03\x91\x02\x03",
		"\x03\x03\x90", "\x03\x04\x90\x03", "\x03\x00\x00",
		"\x03" + strings.Repeat("\xff", 10),
	} {
		_, err := applyDelta(t.Context(), "abc", delta, 1<<20)
		require.Error(t, err, "%x", delta)
	}
	_, err = applyDelta(t.Context(), "abc", "\x03\x04\x90\x03\x01d", 3)
	require.ErrorContains(t, err, "limit")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = applyDelta(ctx, "abc", "\x03\x03\x90\x03", 10)
	require.ErrorIs(t, err, context.Canceled)
}

func FuzzApplyDelta(f *testing.F) {
	f.Add("abc", "\x03\x04\x90\x03\x01d")
	f.Add("abcdef", "\x06\x03\x91\x02\x03")
	f.Add("abc", "\x03\x00")
	f.Fuzz(func(t *testing.T, base, delta string) {
		if len(base) == 0 || len(base) > 65536 || len(delta) > 65536 {
			t.Skip()
		}
		// Keep the reference decoder's allocation bounded too.
		_, n := binary.Uvarint([]byte(delta))
		if n <= 0 {
			return
		}
		size, n := binary.Uvarint([]byte(delta[n:]))
		if n <= 0 || size > 1<<20 {
			return
		}
		want, wantErr := packfile.PatchDelta([]byte(base), []byte(delta))
		got, err := applyDelta(t.Context(), base, delta, 1<<20)
		if wantErr != nil {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		require.Equal(t, string(want), got)
	})
}
