//nolint:exhaustruct // Fixtures vary the field relevant to each case.
package scm

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-git/go-billy/v6"
	"github.com/go-git/go-billy/v6/osfs"
	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	format "github.com/go-git/go-git/v6/plumbing/format/config"
	"github.com/go-git/go-git/v6/plumbing/format/idxfile"
	"github.com/go-git/go-git/v6/plumbing/format/packfile"
	githash "github.com/go-git/go-git/v6/plumbing/hash"
	"github.com/go-git/go-git/v6/storage/filesystem"
	"github.com/stretchr/testify/require"
)

type testPack struct {
	format format.ObjectFormat
	data   []byte
	count  uint32
}

func newTestPack(f format.ObjectFormat) *testPack {
	return &testPack{format: f, data: []byte{'P', 'A', 'C', 'K', 0, 0, 0, 2, 0, 0, 0, 0}}
}

func packHeader(typ plumbing.ObjectType, size uint64) []byte {
	b := byte(typ)<<4 | byte(size&15)
	size >>= 4
	var out []byte
	for size != 0 {
		out = append(out, b|128)
		b, size = byte(size&127), size>>7
	}
	return append(out, b)
}

func (p *testPack) add(t testing.TB, typ plumbing.ObjectType, body string, declared uint64, baseOffset int64, baseID plumbing.Hash) int64 {
	t.Helper()
	offset := int64(len(p.data))
	p.data = append(p.data, packHeader(typ, declared)...)
	switch typ {
	case plumbing.OFSDeltaObject:
		n := uint64(offset - baseOffset)
		encoded := []byte{byte(n & 127)}
		for n >>= 7; n != 0; n >>= 7 {
			n--
			encoded = append([]byte{byte(n&127) | 128}, encoded...)
		}
		p.data = append(p.data, encoded...)
	case plumbing.REFDeltaObject:
		p.data = append(p.data, baseID.Bytes()...)
	}
	var compressed bytes.Buffer
	z := zlib.NewWriter(&compressed)
	_, err := io.WriteString(z, body)
	require.NoError(t, err)
	require.NoError(t, z.Close())
	p.data = append(p.data, compressed.Bytes()...)
	p.count++
	return offset
}

func (p *testPack) finish(t testing.TB) []byte {
	t.Helper()
	binary.BigEndian.PutUint32(p.data[8:12], p.count)
	h, err := githash.FromObjectFormat(p.format)
	require.NoError(t, err)
	h.Write(p.data)
	return append(append([]byte{}, p.data...), h.Sum(nil)...)
}

func blobID(f format.ObjectFormat, text string) plumbing.Hash {
	h := plumbing.NewHasher(f, plumbing.BlobObject, int64(len(text)))
	h.Write([]byte(text))
	return h.Sum()
}

func literalDelta(base, target string) string {
	d := binary.AppendUvarint(nil, uint64(len(base)))
	d = binary.AppendUvarint(d, uint64(len(target)))
	for len(target) > 0 {
		n := min(127, len(target))
		d = append(d, byte(n))
		d = append(d, target[:n]...)
		target = target[n:]
	}
	return string(d)
}

// REF->OFS, OFS->REF, a forward REF base, and siblings at two depths all occur
// in one pack: a -> {ab -> abc -> {abcd, abcx}, ae}.
func mixedTestPack(t testing.TB, f format.ObjectFormat) []byte {
	p := newTestPack(f)
	a := p.add(t, plumbing.BlobObject, "a", 1, 0, plumbing.Hash{})
	d := literalDelta("ab", "abc")
	c := p.add(t, plumbing.REFDeltaObject, d, uint64(len(d)), 0, blobID(f, "ab"))
	d = literalDelta("a", "ab")
	p.add(t, plumbing.OFSDeltaObject, d, uint64(len(d)), a, plumbing.Hash{})
	d = literalDelta("abc", "abcd")
	p.add(t, plumbing.OFSDeltaObject, d, uint64(len(d)), c, plumbing.Hash{})
	d = literalDelta("abc", "abcx")
	p.add(t, plumbing.OFSDeltaObject, d, uint64(len(d)), c, plumbing.Hash{})
	d = literalDelta("a", "ae")
	p.add(t, plumbing.REFDeltaObject, d, uint64(len(d)), 0, blobID(f, "a"))
	return p.finish(t)
}

func TestIndexPackMatchesGit(t *testing.T) {
	binary, err := exec.LookPath("git")
	if err != nil {
		t.Skip("Git fixture checker unavailable")
	}
	for _, f := range []format.ObjectFormat{format.SHA1, format.SHA256} {
		for _, empty := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/empty=%v", f, empty), func(t *testing.T) {
				data := mixedTestPack(t, f)
				if empty {
					data = newTestPack(f).finish(t)
				}
				dir := t.TempDir()
				run := func(args ...string) {
					cmd := exec.CommandContext(t.Context(), binary, args...)
					cmd.Dir = dir
					cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
					out, err := cmd.CombinedOutput()
					require.NoError(t, err, "%s", out)
				}
				run("init", "--bare", "--object-format="+string(f))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "input.pack"), data, 0600))
				run("index-pack", "--index-version=2", "--rev-index", "input.pack")
				// A one-byte cache drops every link but the newest, so each sibling
				// rebuilds its base from the start of the chain.
				for _, cache := range []int64{fetchPackLimits().cacheBytes, 1} {
					limits := fetchPackLimits()
					limits.cacheBytes = cache
					var idx, rev bytes.Buffer
					_, err := indexPack(t.Context(), bytes.NewReader(data), int64(len(data)), f, limits, &idx, &rev)
					require.NoError(t, err)
					for ext, got := range map[string][]byte{"idx": idx.Bytes(), "rev": rev.Bytes()} {
						want, err := os.ReadFile(filepath.Join(dir, "input."+ext))
						require.NoError(t, err)
						require.Equal(t, want, got, "%s with cache %d", ext, cache)
					}
				}
			})
		}
	}
}

func TestIndexPackRejectsCorruptionAndLimits(t *testing.T) {
	good := mixedTestPack(t, format.SHA1)
	badChecksum := append([]byte{}, good...)
	badChecksum[len(badChecksum)-1] ^= 1
	makeBlob := func(body string, declared uint64) []byte {
		p := newTestPack(format.SHA1)
		p.add(t, plumbing.BlobObject, body, declared, 0, plumbing.Hash{})
		return p.finish(t)
	}
	missing := newTestPack(format.SHA1)
	delta := literalDelta("absent", "new")
	missing.add(t, plumbing.REFDeltaObject, delta, uint64(len(delta)), 0, blobID(format.SHA1, "absent"))
	duplicate := newTestPack(format.SHA1)
	duplicate.add(t, plumbing.BlobObject, "a", 1, 0, plumbing.Hash{})
	duplicate.add(t, plumbing.BlobObject, "a", 1, 0, plumbing.Hash{})
	badBase := newTestPack(format.SHA1)
	badBase.add(t, plumbing.BlobObject, "a", 1, 0, plumbing.Hash{})
	badBase.add(t, plumbing.OFSDeltaObject, literalDelta("a", "b"), 4, 13, plumbing.Hash{})
	oversizedResult := newTestPack(format.SHA1)
	base := oversizedResult.add(t, plumbing.BlobObject, "a", 1, 0, plumbing.Hash{})
	oversized := binary.AppendUvarint([]byte{1}, 1<<40)
	oversizedResult.add(t, plumbing.OFSDeltaObject, string(oversized), uint64(len(oversized)), base, plumbing.Hash{})
	invalidDelta := newTestPack(format.SHA1)
	base = invalidDelta.add(t, plumbing.BlobObject, "a", 1, 0, plumbing.Hash{})
	invalidDelta.add(t, plumbing.OFSDeltaObject, "\x01\x01\x00", 3, base, plumbing.Hash{})
	// A plain blob is only streamed, so a huge declared size allocates nothing;
	// the missing content fails inflation.
	oversizedHeader := newTestPack(format.SHA1)
	oversizedHeader.data = append(oversizedHeader.data, packHeader(plumbing.BlobObject, 1<<40)...)
	oversizedHeader.count = 1
	tooMany := newTestPack(format.SHA1)
	tooMany.count = ^uint32(0)
	// The base must be held to apply its delta: one copy of all six bytes.
	largeBase := newTestPack(format.SHA1)
	base = largeBase.add(t, plumbing.BlobObject, "abcdef", 6, 0, plumbing.Hash{})
	largeBase.add(t, plumbing.OFSDeltaObject, "\x06\x06\x90\x06", 4, base, plumbing.Hash{})
	for _, tc := range []struct {
		name   string
		data   []byte
		change func(*packLimits)
		want   string
	}{
		{"checksum", badChecksum, nil, "checksum"},
		{"truncated", good[:len(good)-1], nil, ""},
		{"trailing-data", append(append([]byte{}, good...), 0), nil, "trailing"},
		{"short-inflation", makeBlob("a", 2), nil, "size mismatch"},
		{"long-inflation", makeBlob("ab", 1), nil, "size mismatch"},
		{"missing-base", missing.finish(t), nil, "no base"},
		{"duplicate", duplicate.finish(t), nil, "duplicate"},
		{"non-record-base", badBase.finish(t), nil, "not a pack record"},
		{"oversized-result", oversizedResult.finish(t), nil, "limit"},
		{"bad-instruction", invalidDelta.finish(t), nil, "literal"},
		{"oversized-header", oversizedHeader.finish(t), nil, ""},
		{"oversized-count", tooMany.finish(t), nil, ""},
		{"delta-budget", good, func(l *packLimits) { l.objectBytes = 2 }, "instruction bytes"},
		{"base-budget", largeBase.finish(t), func(l *packLimits) { l.objectBytes = 5 }, "exceeds 5 bytes"},
		{"depth-budget", good, func(l *packLimits) { l.depth = 1 }, "chain exceeds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limits := fetchPackLimits()
			if tc.change != nil {
				tc.change(&limits)
			}
			var idx bytes.Buffer
			_, err := indexPack(t.Context(), bytes.NewReader(tc.data), int64(len(tc.data)), format.SHA1, limits, &idx, nil)
			require.Error(t, err)
			if tc.want != "" {
				require.ErrorContains(t, err, tc.want)
			}
			require.Empty(t, idx.Bytes(), "an invalid pack must not produce an index")
		})
	}
}

// A resolver reuses its chain across trees, so finished links must not keep
// their content reachable through the slice's backing array.
func TestResolverReleasesFinishedChains(t *testing.T) {
	data := mixedTestPack(t, format.SHA1)
	table, err := scanPack(t.Context(), bytes.NewReader(data), format.SHA1, fetchPackLimits())
	require.NoError(t, err)
	r := &resolver{ctx: t.Context(), f: bytes.NewReader(data), t: table, limits: fetchPackLimits(),
		cacheBytes: fetchPackLimits().cacheBytes, refs: new(sync.Mutex), hasRefs: len(table.refChildren) > 0,
		input: bufio.NewReaderSize(nil, 8192)}
	for i := range table.objects {
		require.NoError(t, r.tree(i))
	}
	require.Positive(t, cap(r.chain))
	for _, link := range r.chain[:cap(r.chain)] {
		require.Empty(t, link.content)
	}
}

// Limits bound content held in memory, never what a pack may contain: a plain
// object of any size is only streamed through the hasher.
func TestIndexPackStreamsLargePlainObjects(t *testing.T) {
	p := newTestPack(format.SHA1)
	p.add(t, plumbing.BlobObject, "abcdef", 6, 0, plumbing.Hash{})
	data := p.finish(t)
	limits := fetchPackLimits()
	limits.objectBytes = 2
	var idx bytes.Buffer
	_, err := indexPack(t.Context(), bytes.NewReader(data), int64(len(data)), format.SHA1, limits, &idx, nil)
	require.NoError(t, err)
	require.NotEmpty(t, idx.Bytes())
}

// Cancel after a deterministic number of checks, without timer races. Passes
// run on several goroutines, so the count is atomic.
type packCancelContext struct {
	context.Context
	cancel context.CancelFunc
	checks atomic.Int32
}

func newPackCancelContext(ctx context.Context, cancel context.CancelFunc, checks int32) *packCancelContext {
	c := &packCancelContext{Context: ctx, cancel: cancel}
	c.checks.Store(checks)
	return c
}

func (c *packCancelContext) Err() error {
	if c.checks.Add(-1) == 0 {
		c.cancel()
	}
	return c.Context.Err()
}

type cancelPackRead struct {
	io.ReaderAt
	cancel context.CancelFunc
	end    int64
}

func (r cancelPackRead) ReadAt(p []byte, off int64) (int, error) {
	// First pass starts at zero; the footer is at end. A different offset is
	// the resolving pass rereading an object's compressed content.
	if off > 0 && off < r.end {
		r.cancel()
	}
	return r.ReaderAt.ReadAt(p, off)
}

func TestIndexPackCancellation(t *testing.T) {
	p := newTestPack(format.SHA1)
	p.add(t, plumbing.BlobObject, strings.Repeat("x", 4<<20), 4<<20, 0, plumbing.Hash{})
	data := p.finish(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	counted := newPackCancelContext(ctx, cancel, 30)
	_, err := indexPack(counted, bytes.NewReader(data), int64(len(data)), format.SHA1, fetchPackLimits(), io.Discard, nil)
	require.ErrorIs(t, err, context.Canceled, "cancel while inflating one large record")

	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	data = mixedTestPack(t, format.SHA1)
	reader := cancelPackRead{bytes.NewReader(data), cancel, int64(len(data) - 20)}
	_, err = indexPack(ctx, reader, int64(len(data)), format.SHA1, fetchPackLimits(), io.Discard, nil)
	require.ErrorIs(t, err, context.Canceled, "cancel during delta resolution")
}

func newPackTestStorage(t *testing.T, ctx context.Context) *packStorage {
	t.Helper()
	dest := t.TempDir()
	repo, err := git.PlainInit(dest, true)
	require.NoError(t, err)
	s := &packStorage{Storage: repo.Storer.(*filesystem.Storage), ctx: ctx,
		dir: filepath.Join(dest, "objects", "pack"), limits: fetchPackLimits()}
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	return s
}

func TestPackWriterPublishesAndCleansUp(t *testing.T) {
	data := mixedTestPack(t, format.SHA1)
	for _, mode := range []string{"success", "corrupt", "cancel", "cancel-write", "cancel-inflate", "existing-index", "empty"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			s := newPackTestStorage(t, ctx)
			input := append([]byte{}, data...)
			if mode == "corrupt" {
				input[len(input)-1] ^= 1
			}
			if mode == "empty" {
				input = nil
			}
			if mode == "cancel-inflate" {
				p := newTestPack(format.SHA1)
				p.add(t, plumbing.BlobObject, strings.Repeat("x", 4<<20), 4<<20, 0, plumbing.Hash{})
				input = p.finish(t)
				s.ctx = newPackCancelContext(ctx, cancel, 30)
			}
			w, err := s.PackfileWriter()
			require.NoError(t, err)
			if mode == "cancel-write" {
				cancel()
			}
			_, err = io.Copy(w, bytes.NewReader(input))
			if mode == "cancel-write" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if mode == "cancel" {
				cancel()
			}
			var existing string
			if mode == "existing-index" {
				existing = filepath.Join(s.dir, fmt.Sprintf("pack-%x.idx", input[len(input)-20:]))
				require.NoError(t, os.WriteFile(existing, []byte("keep"), 0600))
			}
			err = w.Close()
			if mode == "success" || mode == "empty" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			if strings.HasPrefix(mode, "cancel") {
				require.ErrorIs(t, err, context.Canceled)
			}
			require.Equal(t, err, w.Close(), "Close is idempotent")
			_, err = w.Write([]byte("late"))
			require.ErrorIs(t, err, os.ErrClosed)
			entries, err := os.ReadDir(s.dir)
			require.NoError(t, err)
			switch mode {
			case "success":
				require.Len(t, entries, 3)
				for _, name := range []string{"a", "ab", "abc", "abcd", "abcx", "ae"} {
					require.NoError(t, s.HasEncodedObject(blobID(format.SHA1, name)))
				}
			case "existing-index":
				require.Len(t, entries, 1, "new pack must be rolled back")
				got, err := os.ReadFile(existing)
				require.NoError(t, err)
				require.Equal(t, "keep", string(got))
			default:
				require.Empty(t, entries, "failed fetch left files behind")
			}
		})
	}
}

type packTestWriter func([]byte) (int, error)

func (w packTestWriter) Write(p []byte) (int, error) { return w(p) }

func TestIndexPackOutputFailure(t *testing.T) {
	data := mixedTestPack(t, format.SHA1)
	fail := packTestWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe })
	for _, reverse := range []bool{false, true} {
		out, rev := io.Discard, io.Discard
		if reverse {
			rev = fail
		} else {
			out = fail
		}
		_, err := indexPack(t.Context(), bytes.NewReader(data), int64(len(data)), format.SHA1, fetchPackLimits(), out, rev)
		require.ErrorIs(t, err, io.ErrClosedPipe)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	w := packTestWriter(func(p []byte) (int, error) { cancel(); return len(p), nil })
	_, err := indexPack(ctx, bytes.NewReader(data), int64(len(data)), format.SHA1, fetchPackLimits(), w, nil)
	require.ErrorIs(t, err, context.Canceled)
}

func FuzzIndexPack(f *testing.F) {
	f.Add(mixedTestPack(f, format.SHA1))
	f.Add(newTestPack(format.SHA1).finish(f))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		limits := packLimits{objectBytes: 64 << 10, cacheBytes: 1 << 10, depth: 32}
		_, _ = indexPack(t.Context(), bytes.NewReader(data), int64(len(data)), format.SHA1, limits, io.Discard, nil)
	})
}

// openBenchPack maps an existing pack the way a fetch does before resolving it.
func openBenchPack(tb testing.TB, path string) (billy.File, int64) {
	tb.Helper()
	f, err := osfs.New(filepath.Dir(path), osfs.WithMmap()).Open(filepath.Base(path))
	require.NoError(tb, err)
	tb.Cleanup(func() { f.Close() })
	info, err := f.Stat()
	require.NoError(tb, err)
	return f, info.Size()
}

// Check a real repository pack without copying it or printing its contents.
func TestIndexExistingPack(t *testing.T) {
	path := os.Getenv("BETTERLEAKS_BENCH_PACK")
	if path == "" {
		t.Skip("set BETTERLEAKS_BENCH_PACK to an existing SHA-1 pack with a .idx")
	}
	f, size := openBenchPack(t, path)
	want, err := os.Open(strings.TrimSuffix(path, ".pack") + ".idx")
	require.NoError(t, err)
	defer want.Close()
	wantHash, gotHash := sha256.New(), sha256.New()
	_, err = io.Copy(wantHash, want)
	require.NoError(t, err)
	_, err = indexPack(t.Context(), f, size, format.SHA1, fetchPackLimits(), gotHash, io.Discard)
	require.NoError(t, err)
	require.Equal(t, wantHash.Sum(nil), gotHash.Sum(nil), "index must match Git byte for byte")
	t.Logf("pack bytes: %d; index SHA-256: %x", size, gotHash.Sum(nil))
}

// Supply an existing pack to compare both indexers offline, in separate processes
// when measuring RSS. No repository content or findings are printed.
func BenchmarkIndexPack(b *testing.B) {
	path := os.Getenv("BETTERLEAKS_BENCH_PACK")
	if path == "" {
		b.Skip("set BETTERLEAKS_BENCH_PACK to an existing SHA-1 pack")
	}
	f, size := openBenchPack(b, path)
	mode := os.Getenv("BETTERLEAKS_BENCH_INDEXER")
	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if mode == "upstream" {
			_, err := f.Seek(0, io.SeekStart)
			require.NoError(b, err)
			w := new(idxfile.Writer)
			parser := packfile.NewParser(f, packfile.WithScannerObservers(w))
			_, err = parser.Parse()
			require.NoError(b, err)
			idx, err := w.Index()
			require.NoError(b, err)
			h, err := githash.FromObjectFormat(format.SHA1)
			require.NoError(b, err)
			require.NoError(b, idxfile.Encode(io.Discard, h, idx))
		} else {
			_, err := indexPack(b.Context(), f, size, format.SHA1, fetchPackLimits(), io.Discard, nil)
			require.NoError(b, err)
		}
	}
}
