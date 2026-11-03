package sources

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	gitMetadataMaxBytes   int64 = 512 << 20
	gitMetadataMaxFile    int64 = 256 << 20
	gitMetadataMaxEntries       = 100_000
	gitMetadataMaxDepth         = 64
	gitMetadataReadLimit  int64 = 1 << 20
)

// One budget covers all worktrees, refs, reflogs, indexes, and mailmaps copied
// during setup. Directory enumeration is incremental, including ignored entries.
type gitMetadataCopier struct {
	remainingBytes   int64
	remainingEntries int
	maxFileBytes     int64
	maxDepth         int
	roots            map[string]*os.Root
	buffer           []byte
}

func newGitMetadataCopier() *gitMetadataCopier {
	return &gitMetadataCopier{
		remainingBytes: gitMetadataMaxBytes, remainingEntries: gitMetadataMaxEntries,
		maxFileBytes: gitMetadataMaxFile, maxDepth: gitMetadataMaxDepth,
		roots: make(map[string]*os.Root), buffer: make([]byte, 32*1024),
	}
}

func (c *gitMetadataCopier) Close() {
	for _, root := range c.roots {
		_ = root.Close()
	}
}

// Pin source directories for the lifetime of setup. Descendant roots are opened
// through the existing handle, so replacing a directory with a symlink cannot
// redirect later reads outside the original tree.
func (c *gitMetadataCopier) root(dir string) (*os.Root, error) {
	dir = filepath.Clean(dir)
	if root := c.roots[dir]; root != nil {
		return root, nil
	}
	var root *os.Root
	var err error
	var parent *os.Root
	var relative string
	longest := -1
	for base, candidate := range c.roots {
		if rel, relErr := filepath.Rel(base, dir); relErr == nil && filepath.IsLocal(rel) && len(base) > longest {
			parent, relative, longest = candidate, rel, len(base)
		}
	}
	if parent != nil {
		root, err = parent.OpenRoot(relative)
	} else {
		root, err = os.OpenRoot(dir)
	}
	if err != nil {
		return nil, err
	}
	c.roots[dir] = root
	return root, nil
}

func (c *gitMetadataCopier) takeEntry() error {
	if c.remainingEntries <= 0 {
		return errors.New("Git metadata entry limit exceeded")
	}
	c.remainingEntries--
	return nil
}

// openGitMetadata checks the opened handle before reading from it. Root bounds
// path resolution, SameFile detects replacements, and nonblocking opens avoid
// hanging if a regular file is replaced with a FIFO during the open.
func openGitMetadata(root *os.Root, name string, directory bool) (*os.File, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	valid := func(info fs.FileInfo) bool {
		if directory {
			return info.IsDir()
		}
		return info.Mode().IsRegular()
	}
	if !valid(before) {
		return nil, fmt.Errorf("not a regular file or directory of the required type: %s", name)
	}
	f, err := root.OpenFile(name, os.O_RDONLY|gitMetadataNonblock, 0)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !valid(after) || !os.SameFile(before, after) {
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("Git metadata changed while opening: %s", name)
	}
	return f, nil
}

// readGitFile reads a bounded regular metadata file, including configuration.
// The limit is enforced on the open handle even if the file grows while read.
func readGitFile(path string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := openGitMetadata(root, filepath.Base(path), false)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, gitMetadataReadLimit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > gitMetadataReadLimit {
		return nil, fmt.Errorf("Git metadata file exceeds read limit: %s", path)
	}
	return data, nil
}

var (
	gitRefFiles = []string{"HEAD", "packed-refs", "shallow", "ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "BISECT_HEAD", "REBASE_HEAD", "AUTO_MERGE"}
	gitRefDirs  = []string{"refs", "logs", "reftable"}
)

func (c *gitMetadataCopier) copyRefs(ctx context.Context, src, dst string) error {
	root, err := c.root(src)
	if err != nil {
		return err
	}
	for _, name := range gitRefFiles {
		if err := c.takeEntry(); err != nil {
			return err
		}
		if err := c.copyFileFromRoot(ctx, root, name, filepath.Join(dst, name)); err != nil {
			return err
		}
	}
	for _, name := range gitRefDirs {
		if err := c.copyTree(ctx, root, name, filepath.Join(dst, name), 0); err != nil {
			return err
		}
	}
	return nil
}

func (c *gitMetadataCopier) forEachEntry(ctx context.Context, root *os.Root, name string, fn func(fs.DirEntry) error) error {
	dir, err := openGitMetadata(root, name, true)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	return c.readEntries(ctx, dir, fn)
}

func (c *gitMetadataCopier) readEntries(ctx context.Context, dir *os.File, fn func(fs.DirEntry) error) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := dir.ReadDir(128)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		for _, entry := range entries {
			if err := c.takeEntry(); err != nil {
				return err
			}
			if err := fn(entry); err != nil {
				return err
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

func (c *gitMetadataCopier) copyTree(ctx context.Context, root *os.Root, name, dst string, depth int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth > c.maxDepth {
		return errors.New("Git metadata directory depth limit exceeded")
	}
	dir, err := openGitMetadata(root, name, true)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	return c.readEntries(ctx, dir, func(entry fs.DirEntry) error {
		next := filepath.Join(name, entry.Name())
		target := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			return c.copyTree(ctx, root, next, target, depth+1)
		}
		if strings.HasSuffix(entry.Name(), ".lock") {
			return nil
		}
		return c.copyFileFromRoot(ctx, root, next, target)
	})
}

func (c *gitMetadataCopier) copyFile(ctx context.Context, src, dst string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := c.takeEntry(); err != nil {
		return err
	}
	root, err := c.root(filepath.Dir(src))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return c.copyFileFromRoot(ctx, root, filepath.Base(src), dst)
}

func (c *gitMetadataCopier) copyFileFromRoot(ctx context.Context, root *os.Root, name, dst string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	in, err := openGitMetadata(root, name, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer in.Close()
	limit := min(c.maxFileBytes, c.remainingBytes)
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if info.Size() > limit {
		return fmt.Errorf("Git metadata byte limit exceeded: %s", name)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	// Bound the stream itself as well as its initial size. Probe for excess
	// without writing a byte beyond the remaining budget.
	copyErr := c.copyContents(ctx, in, out, limit)
	return errors.Join(copyErr, out.Close())
}

func (c *gitMetadataCopier) copyContents(ctx context.Context, in io.Reader, out io.Writer, limit int64) error {
	n, copyErr := io.CopyBuffer(struct{ io.Writer }{out}, io.LimitReader(gitContextReader{ctx, in}, limit), c.buffer)
	c.remainingBytes -= n
	if copyErr == nil {
		var extra [1]byte
		read, err := (gitContextReader{ctx, in}).Read(extra[:])
		if read != 0 {
			copyErr = errors.New("Git metadata byte limit exceeded while copying")
		} else if err != nil && !errors.Is(err, io.EOF) {
			copyErr = err
		}
	}
	return copyErr
}

type gitContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r gitContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
