//nolint:exhaustruct // Test fixtures specify only the fields relevant to each scenario.
package gogit

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	format "github.com/go-git/go-git/v6/plumbing/format/config"

	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/cache"
	"github.com/go-git/go-git/v6/plumbing/filemode"
	"github.com/go-git/go-git/v6/plumbing/format/packfile"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/stretchr/testify/require"
)

func diskTestObject(i int) *storedObject {
	return &storedObject{id: plumbing.NewHash(fmt.Sprintf("%040x", i+1)), kind: plumbing.BlobObject, raw: strings.Repeat(string(rune('a'+i%26)), 1<<20)}
}

func TestDiskObjectCache(t *testing.T) {
	c := &diskObjectCache{segmentSize: 1 << 20}
	defer c.close()
	first := diskTestObject(0)
	c.put(first)
	info, err := c.file.Stat()
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
	read, ok := c.get(first.id)
	require.True(t, ok)
	require.Equal(t, first, read)
	for i := 1; i < 20; i++ {
		c.put(diskTestObject(i))
	}
	_, ok = c.get(first.id)
	require.False(t, ok)
	require.Equal(t, first.raw, read.raw, "eviction must not overwrite borrowed strings")
	last := diskTestObject(19)
	read, ok = c.get(last.id)
	require.True(t, ok)
	require.Equal(t, last, read)
	info, err = c.file.Stat()
	require.NoError(t, err)
	require.LessOrEqual(t, info.Size(), int64(8<<20))
	name := c.file.Name()
	c.close()
	_, err = os.Stat(name)
	require.True(t, os.IsNotExist(err))
}

func TestDiskObjectCacheConcurrent(t *testing.T) {
	c := &diskObjectCache{segmentSize: 1 << 20}
	defer c.close()
	var wg sync.WaitGroup
	for worker := range 4 {
		wg.Go(func() {
			for i := range 10 {
				o := diskTestObject(worker*10 + i)
				c.put(o)
				if read, ok := c.get(o.id); ok && *read != *o {
					t.Errorf("cache returned different content for %s", o.id)
				}
			}
		})
	}
	wg.Wait()
}

func TestDiskObjectCacheUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(path, nil, 0600))
	t.Setenv("TMPDIR", path)
	t.Setenv("TMP", path)
	t.Setenv("TEMP", path)
	c := &diskObjectCache{segmentSize: 1 << 20}
	defer c.close()
	o := diskTestObject(0)
	c.put(o)
	require.True(t, c.failed)
	_, ok := c.get(o.id)
	require.False(t, ok)
}

func patchTestKey(i int) patchKey {
	return patchKey{to: plumbing.NewHash(fmt.Sprintf("%040x", i+1))}
}

func TestPatchCacheBoundsAndOwnership(t *testing.T) {
	c := &patchCache{}
	first := []textAddition{{raw: strings.Repeat("a", 128<<10), line: 7}}
	c.put(patchTestKey(0), first)
	borrowed, ok := c.get(patchTestKey(0))
	require.True(t, ok)
	for i := 1; i < 300; i++ {
		c.put(patchTestKey(i), []textAddition{{raw: strings.Repeat("b", 128<<10), line: i}})
		require.LessOrEqual(t, c.bytes, patchCacheBudget)
	}
	_, ok = c.get(patchTestKey(0))
	require.False(t, ok)
	require.Equal(t, first, borrowed, "eviction must not mutate an in-flight patch")
	c.put(patchTestKey(300), []textAddition{{raw: strings.Repeat("x", maxCachedPatch)}})
	_, ok = c.get(patchTestKey(300))
	require.False(t, ok)
	c.put(patchTestKey(301), nil)
	value, ok := c.get(patchTestKey(301))
	require.True(t, ok, "a deletion-only text change is a valid empty result")
	require.Empty(t, value)
}

func TestPatchCacheConcurrent(t *testing.T) {
	c := &patchCache{}
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			for i := range 1000 {
				key := patchTestKey(i + worker*1000)
				c.put(key, []textAddition{{raw: "TOKEN\n", line: i}})
				if value, ok := c.get(key); ok && (len(value) != 1 || value[0].line != i || value[0].raw != "TOKEN\n") {
					t.Errorf("patch content changed for %s", key.to)
				}
			}
		})
	}
	wg.Wait()
}

func TestCachedPatchCallbacks(t *testing.T) {
	objects := &objectCache{cache.NewObjectLRU(1 << 20)}
	from := &storedObject{id: plumbing.NewHash(strings.Repeat("1", 40)), kind: plumbing.BlobObject, raw: "first\nold\nlast\n"}
	to := &storedObject{id: plumbing.NewHash(strings.Repeat("2", 40)), kind: plumbing.BlobObject, raw: "first\nTOKEN\nlast\n"}
	objects.Put(from)
	objects.Put(to)
	w := worker{source: &Source{}, store: &objectStorage{ctx: t.Context(), objects: objects}, patches: &patchCache{}, maxBlob: 1 << 20}
	change := &object.Change{
		From: object.ChangeEntry{Name: "old.txt", TreeEntry: object.TreeEntry{Hash: from.id, Mode: filemode.Regular}},
		To:   object.ChangeEntry{Name: "new.txt", TreeEntry: object.TreeEntry{Hash: to.id, Mode: filemode.Regular}},
	}
	key := patchKey{from.id, to.id}
	failed := errors.New("callback failed")
	yieldError := func(sources.Fragment, error) error { return failed }
	require.ErrorIs(t, w.change(t.Context(), change, nil, yieldError), failed)
	_, ok := w.patches.get(key)
	require.False(t, ok, "failed emission must not populate the cache")
	var got []sources.Fragment
	for _, commit := range []string{"first-commit", "second-commit"} {
		attrs := map[string]string{sources.AttrGitSHA: commit, sources.AttrPath: commit + ".txt"}
		yield := func(fragment sources.Fragment, err error) error {
			require.NoError(t, err)
			got = append(got, fragment)
			return nil
		}
		require.NoError(t, w.change(t.Context(), change, attrs, yield))
		// The second invocation must use only cached additions and the new
		// callback, without reading an object or retaining the old attributes.
		w.store = nil
	}
	require.Len(t, got, 2)
	for i, commit := range []string{"first-commit", "second-commit"} {
		require.Equal(t, "TOKEN\n", got[i].Raw)
		require.Equal(t, 2, got[i].StartLine)
		require.Equal(t, commit, got[i].Attr(sources.AttrGitSHA))
		require.Equal(t, commit+".txt", got[i].Attr(sources.AttrPath))
	}
	require.ErrorIs(t, w.change(t.Context(), change, nil, yieldError), failed)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, w.change(ctx, change, nil, yieldError), context.Canceled)
}

func TestPatchCachePreservesBinaryArchiveMembers(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	member, err := writer.Create("secret.bin")
	require.NoError(t, err)
	content := "\x00TOKEN_BINARY_MEMBER\x00\n"
	_, err = member.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	objects := &objectCache{cache.NewObjectLRU(1 << 20)}
	to := &storedObject{id: plumbing.NewHash(strings.Repeat("2", 40)), kind: plumbing.BlobObject, raw: archive.String()}
	objects.Put(to)
	w := worker{source: &Source{MaxArchiveDepth: 1}, store: &objectStorage{ctx: t.Context(), objects: objects}, patches: &patchCache{}, maxBlob: 1 << 20}
	change := &object.Change{
		From: object.ChangeEntry{Name: "archive.zip", TreeEntry: object.TreeEntry{Hash: plumbing.NewHash(strings.Repeat("1", 40)), Mode: filemode.Regular}},
		To:   object.ChangeEntry{Name: "archive.zip", TreeEntry: object.TreeEntry{Hash: to.id, Mode: filemode.Regular}},
	}
	for _, commit := range []string{"first-commit", "second-commit"} {
		var got []sources.Fragment
		attrs := map[string]string{sources.AttrGitSHA: commit, sources.AttrPath: "archive.zip"}
		yield := func(f sources.Fragment, err error) error {
			require.NoError(t, err)
			got = append(got, f)
			return nil
		}
		require.NoError(t, w.change(t.Context(), change, attrs, yield))
		require.Len(t, got, 1)
		require.Equal(t, content, got[0].Raw)
		require.Equal(t, commit, got[0].Attr(sources.AttrGitSHA))
		require.Equal(t, "archive.zip!secret.bin", got[0].Attr(sources.AttrPath))
	}
	require.Empty(t, w.patches.entries, "archive extraction must run for every commit")
}

func TestObjectCacheDoesNotRetainPackReaders(t *testing.T) {
	c := &objectCache{cache.NewObjectLRU(1024)}
	id := plumbing.NewHash(strings.Repeat("a", 40))
	lazy := packfile.NewFSObject(id, plumbing.CommitObject, 0, 1, nil, nil, nil, "", c)
	c.Put(lazy)
	_, found := c.Get(id)
	require.False(t, found)
	memory := plumbing.NewMemoryObject(plumbing.FromObjectFormat(format.SHA1))
	memory.SetType(plumbing.BlobObject)
	writer, err := memory.Writer()
	require.NoError(t, err)
	_, err = writer.Write([]byte("data"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	c.Put(memory)
	actual, found := c.Get(memory.Hash())
	require.True(t, found)
	require.Same(t, memory, actual)
	c.Clear()
	_, found = c.Get(memory.Hash())
	require.False(t, found)
}

func TestCachedTextDeltaBase(t *testing.T) {
	base := &storedObject{kind: plumbing.BlobObject, raw: "abc"}
	reader, err := base.Reader()
	require.NoError(t, err)
	seeker, ok := reader.(io.Seeker)
	require.True(t, ok)
	_, err = seeker.Seek(1, io.SeekStart)
	require.NoError(t, err)
	raw, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, "bc", string(raw))
	require.NoError(t, reader.Close())
	_, err = base.Writer()
	require.Error(t, err)
	// Copy all three source bytes, then append one literal byte. The source's
	// cached representation must remain usable by go-git's delta reconstruction.
	target := plumbing.NewMemoryObject(plumbing.FromObjectFormat(format.SHA1))
	require.NoError(t, packfile.ApplyDelta(target, base, bytes.NewBuffer([]byte{3, 4, 0x90, 3, 1, 'd'})))
	result, err := target.Reader()
	require.NoError(t, err)
	defer result.Close()
	raw, err = io.ReadAll(result)
	require.NoError(t, err)
	require.Equal(t, "abcd", string(raw))
	require.Equal(t, plumbing.BlobObject, base.Type())
	require.Equal(t, int64(3), base.Size())
}

type slowHashObject struct {
	plumbing.EncodedObject
	entered, release chan struct{}
	once             sync.Once
}

func (o *slowHashObject) Hash() plumbing.Hash {
	o.once.Do(func() { close(o.entered); <-o.release })
	return o.EncodedObject.Hash()
}

func TestObjectHashDoesNotBlockCache(t *testing.T) {
	c := &objectCache{cache.NewObjectLRU(1024)}
	seed := &storedObject{kind: plumbing.BlobObject, id: plumbing.NewHash(strings.Repeat("1", 40)), raw: "seed"}
	c.Put(seed)
	obj := &slowHashObject{EncodedObject: &storedObject{kind: plumbing.BlobObject, id: plumbing.NewHash(strings.Repeat("2", 40)), raw: "slow"}, entered: make(chan struct{}), release: make(chan struct{})}
	put := make(chan struct{})
	defer func() { close(obj.release); <-put }()
	go func() { c.Put(obj); close(put) }()
	<-obj.entered
	lookup := make(chan bool, 1)
	go func() { _, ok := c.Get(seed.id); lookup <- ok }()
	select {
	case ok := <-lookup:
		require.True(t, ok)
	case <-time.After(2 * time.Second):
		t.Fatal("hashing an unpublished object blocked unrelated cache lookup")
	}
}
