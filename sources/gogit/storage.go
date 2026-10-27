package gogit

import (
	"bufio"
	"compress/zlib"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/betterleaks/betterleaks/v2/internal/gitfs"
	"github.com/betterleaks/betterleaks/v2/internal/gitobj"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
)

// repositoryFS routes shared metadata to commondir and per-worktree state to
// gitdir. Both sides are confined independently by os.Root.
type repositoryFS struct {
	billy.Filesystem
	common billy.Filesystem
}

func (f repositoryFS) target(name string) billy.Filesystem {
	if f.common == nil {
		return f.Filesystem
	}
	name = filepath.ToSlash(filepath.Clean(name))
	for _, p := range []string{"refs/bisect", "refs/rewritten", "refs/worktree"} {
		if name == p || strings.HasPrefix(name, p+"/") {
			return f.Filesystem
		}
	}
	if name == "logs/HEAD" {
		return f.Filesystem
	}
	first, _, _ := strings.Cut(name, "/")
	switch first {
	case "objects", "refs", "packed-refs", "config", "branches", "hooks", "info", "remotes", "logs", "shallow", "worktrees":
		return f.common
	}
	return f.Filesystem
}
func (f repositoryFS) Open(n string) (billy.File, error) { return f.target(n).Open(n) }
func (f repositoryFS) OpenFile(n string, flags int, mode os.FileMode) (billy.File, error) {
	return f.target(n).OpenFile(n, flags, mode)
}
func (f repositoryFS) Stat(n string) (os.FileInfo, error)  { return f.target(n).Stat(n) }
func (f repositoryFS) Lstat(n string) (os.FileInfo, error) { return f.target(n).Lstat(n) }
func (f repositoryFS) ReadDir(n string) ([]os.FileInfo, error) {
	entries, err := f.target(n).ReadDir(n)
	if err != nil || f.common == nil || filepath.Clean(n) != "refs" {
		return entries, err
	}
	// Listing common refs alone cannot discover namespaces that exist only in
	// the selected worktree. Replace the common private namespaces with this
	// worktree's entries, just as target routes subsequent reads.
	private := func(name string) bool { return name == "bisect" || name == "rewritten" || name == "worktree" }
	entries = slices.DeleteFunc(entries, func(e os.FileInfo) bool { return private(e.Name()) })
	local, err := f.Filesystem.ReadDir(n)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, entry := range local {
		if private(entry.Name()) {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// An alternate names an object directory, whose basename need not be objects.
// Expose only that directory through the scanner's logical objects/ namespace.
type objectDirectoryFS struct{ billy.Filesystem }

func objectPath(name string) string {
	name = filepath.ToSlash(filepath.Clean(name))
	if name == "objects" {
		return "."
	}
	if strings.HasPrefix(name, "objects/") {
		return strings.TrimPrefix(name, "objects/")
	}
	return "../" + name // os.Root rejects access outside the object directory.
}
func (f objectDirectoryFS) Open(name string) (billy.File, error) {
	return f.Filesystem.Open(objectPath(name))
}
func (f objectDirectoryFS) OpenFile(name string, flags int, mode os.FileMode) (billy.File, error) {
	return f.Filesystem.OpenFile(objectPath(name), flags, mode)
}
func (f objectDirectoryFS) Stat(name string) (os.FileInfo, error) {
	return f.Filesystem.Stat(objectPath(name))
}
func (f objectDirectoryFS) Lstat(name string) (os.FileInfo, error) {
	return f.Filesystem.Lstat(objectPath(name))
}
func (f objectDirectoryFS) ReadDir(name string) ([]os.FileInfo, error) {
	return f.Filesystem.ReadDir(objectPath(name))
}
func alternateFS(path string) readOnlyFS {
	return readOnlyFS{Filesystem: objectDirectoryFS{gitfs.New(path)}, objectRoot: path, pool: nil}
}

func (s *objectStorage) Filesystem() billy.Filesystem    { return s.fs }
func (s *objectStorage) Config() (*config.Config, error) { return s.cfg, nil }
func (s *objectStorage) loadConfig() error {
	raw, err := readLimited(s.fs, "config", 16<<20)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	c, err := parseRepositoryConfig(raw)
	if err != nil {
		return err
	}
	if err := checkExtensions(c); err != nil {
		return err
	}
	worktreeConfig, _ := parseConfigBool(c.Raw.Section("extensions").Option("worktreeconfig"))
	if worktreeConfig {
		worktree, err := readLimited(s.fs, "config.worktree", 16<<20)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if worktree != "" {
			overlay, err := parseRepositoryConfig(worktree)
			if err != nil {
				return err
			}
			mergeWorktreeConfig(c.Raw, overlay.Raw)
			c, err = projectRepositoryConfig(c.Raw)
			if err != nil {
				return err
			}
		}
	}
	format := strings.ToLower(c.Raw.Section("extensions").Option("objectformat"))
	switch format {
	case "", "sha1":
		c.Extensions.ObjectFormat = gitobj.SHA1
	case "sha256":
		c.Extensions.ObjectFormat = gitobj.SHA256
	default:
		return fmt.Errorf("unsupported Git object format %q", format)
	}
	s.cfg = c
	return nil
}

// Preserve the formats accepted by the v6 source. Silently ignoring a future
// extension could interpret its objects or references incorrectly.
func checkExtensions(c *config.Config) error {
	version := c.Raw.Section("core").Option("repositoryformatversion")
	if version == "" {
		version = "0"
	}
	number, err := strconv.ParseUint(version, 10, 32)
	if err != nil || number > 1 {
		return fmt.Errorf("unsupported Git repository format version %q", version)
	}
	for _, option := range c.Raw.Section("extensions").Options {
		name, value := strings.ToLower(option.Key), strings.ToLower(option.Value)
		switch name {
		case "noop":
			continue
		case "worktreeconfig":
			if _, err := parseConfigBool(value); err == nil {
				continue
			}
		case "noop-v1", "objectformat", "relativeworktrees":
			if number != 1 {
				return fmt.Errorf("core.repositoryformatversion does not support extension: %s", name)
			}
			if name == "noop-v1" || name == "objectformat" && (value == "" || value == "sha1" || value == "sha256") || name == "relativeworktrees" && (value == "true" || value == "false") {
				continue
			}
		}
		return fmt.Errorf("unknown extension: %s", name)
	}
	return nil
}

func (s *objectStorage) readLoose(id gitobj.Hash) (*storedObject, error) {
	hex := id.String()
	for _, fs := range append([]readOnlyFS{s.fs}, s.alternates...) {
		f, err := fs.Open("objects/" + hex[:2] + "/" + hex[2:])
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		obj, err := s.decodeLoose(f, id)
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			return nil, errors.Join(err, closeErr)
		}
		s.keep(obj)
		return obj, nil
	}
	return nil, gitobj.ErrObjectNotFound
}
func (s *objectStorage) decodeLoose(f io.Reader, id gitobj.Hash) (*storedObject, error) {
	z, err := zlib.NewReader(contextReader{s.ctx, f})
	if err != nil {
		return nil, err
	}
	defer z.Close()
	r := bufio.NewReader(z)
	var header strings.Builder
	terminated := false
	for range 64 {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == 0 {
			terminated = true
			break
		}
		header.WriteByte(b)
	}
	kind, size, ok := strings.Cut(header.String(), " ")
	if !ok || !terminated {
		return nil, errors.New("invalid loose Git object header")
	}
	typ, err := plumbing.ParseObjectType(kind)
	if err != nil || typ.IsDelta() || typ == plumbing.AnyObject {
		return nil, errors.New("invalid loose Git object type")
	}
	n, err := strconv.ParseInt(size, 10, 64)
	if err != nil || n < 0 {
		return nil, errors.New("invalid loose Git object size")
	}
	if n > s.limit {
		return nil, limitf("object size %d exceeds reconstruction limit %d", n, s.limit)
	}
	var out strings.Builder
	out.Grow(int(n))
	_, err = io.Copy(&out, io.LimitReader(contextReader{s.ctx, r}, n+1))
	if err != nil {
		return nil, err
	}
	if int64(out.Len()) != n {
		return nil, errors.New("loose Git object size mismatch")
	}
	return &storedObject{id: id, kind: typ, raw: out.String()}, nil
}

func (s *objectStorage) HashesWithPrefix(prefix []byte) ([]gitobj.Hash, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	seen := make(map[gitobj.Hash]struct{})
	for _, p := range s.packs {
		ids, err := p.index.HashesWithPrefix(prefix)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			seen[id] = struct{}{}
		}
	}
	for _, fs := range append([]readOnlyFS{s.fs}, s.alternates...) {
		var dirs []string
		if len(prefix) > 0 {
			dirs = []string{hex.EncodeToString(prefix[:1])}
		} else {
			entries, err := fs.ReadDir("objects")
			if err != nil {
				return nil, err
			}
			for _, e := range entries {
				if len(e.Name()) == 2 {
					if _, err := hex.DecodeString(e.Name()); err == nil {
						dirs = append(dirs, e.Name())
					}
				}
			}
		}
		for _, d := range dirs {
			entries, err := fs.ReadDir("objects/" + d)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			for _, e := range entries {
				h := d + e.Name()
				if len(h) == gitobj.FromObjectFormat(s.cfg.Extensions.ObjectFormat).Size()*2 && gitobj.IsHash(h) && strings.HasPrefix(h, hex.EncodeToString(prefix)) {
					seen[gitobj.NewHash(h)] = struct{}{}
				}
			}
		}
	}
	ids := make([]gitobj.Hash, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	return ids, nil
}

// ForEachHashWithPrefix streams revision candidates. Copies in multiple packs
// or alternate stores may be visited more than once; the resolver only needs
// to retain one eligible candidate to detect a second distinct match.
func (s *objectStorage) ForEachHashWithPrefix(prefix string, yield func(gitobj.Hash) bool) error {
	stopped := false
	visit := func(id gitobj.Hash) bool {
		stopped = !yield(id)
		return !stopped
	}
	for _, pack := range s.packs {
		if err := pack.index.ForEachHashWithPrefix(prefix, visit); err != nil {
			return err
		}
		if stopped {
			return nil
		}
	}
	var dirs []string
	if len(prefix) == 1 {
		for _, digit := range "0123456789abcdef" {
			dirs = append(dirs, prefix+string(digit))
		}
	} else {
		dirs = []string{prefix[:2]}
	}
	size := gitobj.FromObjectFormat(s.cfg.Extensions.ObjectFormat).Size() * 2
	for _, fs := range append([]readOnlyFS{s.fs}, s.alternates...) {
		for _, dir := range dirs {
			if err := s.ctx.Err(); err != nil {
				return err
			}
			entries, err := fs.ReadDir("objects/" + dir)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if err := s.ctx.Err(); err != nil {
					return err
				}
				id := dir + entry.Name()
				if len(id) == size && strings.HasPrefix(id, prefix) && gitobj.IsHash(id) && !visit(gitobj.NewHash(id)) {
					return nil
				}
			}
		}
	}
	return nil
}

func (s *objectStorage) loadRefs() error {
	s.refsOnce.Do(func() { s.refsErr = s.readRefs() })
	return s.refsErr
}
func (s *objectStorage) loadPackedRefs() error {
	s.packedOnce.Do(func() { s.packedErr = s.readPackedRefs() })
	return s.packedErr
}
func (s *objectStorage) readPackedRefs() error {
	s.packedRefs = make(map[gitobj.ReferenceName]*gitobj.Reference)
	if f, err := s.fs.Open("packed-refs"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			if err := s.ctx.Err(); err != nil {
				return err
			}
			line := scanner.Text()
			if line == "" || line[0] == '#' || line[0] == '^' {
				continue
			}
			id, name, ok := strings.Cut(line, " ")
			if !ok {
				return errors.New("malformed packed Git reference")
			}
			ref, err := s.parseRef(name, id)
			if err != nil {
				return err
			}
			s.packedRefs[ref.Name()] = ref
		}
		if err := scanner.Err(); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
func (s *objectStorage) readRefs() error {
	if err := s.loadPackedRefs(); err != nil {
		return err
	}
	s.refs = maps.Clone(s.packedRefs)
	var walk func(string, int) error
	walk = func(path string, depth int) error {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		if depth > 128 {
			return errors.New("git reference nesting exceeds 128")
		}
		entries, err := s.fs.ReadDir(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, e := range entries {
			name := path + "/" + e.Name()
			if e.IsDir() {
				if err := walk(name, depth+1); err != nil {
					return err
				}
				continue
			}
			raw, err := readLimited(s.fs, name, 1<<20)
			if errors.Is(err, os.ErrNotExist) {
				continue // A ref can disappear between listing and opening it.
			}
			if err != nil {
				return err
			}
			ref, err := s.parseRef(name, strings.TrimSpace(raw))
			if err != nil {
				return err
			}
			s.refs[ref.Name()] = ref
		}
		return nil
	}
	if err := walk("refs", 0); err != nil {
		return err
	}
	raw, err := readLimited(s.fs, "HEAD", 1<<20)
	if err != nil {
		return err
	}
	ref, err := s.parseRef("HEAD", strings.TrimSpace(raw))
	if err != nil {
		return err
	}
	s.refs[ref.Name()] = ref
	return nil
}
func (s *objectStorage) parseRef(name, value string) (*gitobj.Reference, error) {
	n := gitobj.ReferenceName(name)
	// Existing refs can have names (for example refs/heads/-r) which v5's
	// creation validator rejects. Storage safety is the relevant constraint.
	if !n.IsSafe() {
		return nil, fmt.Errorf("unsafe Git reference name %q", name)
	}
	if target, ok := strings.CutPrefix(value, "ref: "); ok {
		t := gitobj.ReferenceName(target)
		if !t.IsSafe() {
			return nil, fmt.Errorf("unsafe Git symbolic reference target %q", target)
		}
		return gitobj.NewSymbolicReference(n, t), nil
	}
	if !gitobj.IsHash(value) || len(value) != gitobj.FromObjectFormat(s.cfg.Extensions.ObjectFormat).Size()*2 {
		return nil, fmt.Errorf("invalid Git ref %s", name)
	}
	return gitobj.NewHashReference(n, gitobj.NewHash(value)), nil
}
func (s *objectStorage) Reference(name gitobj.ReferenceName) (*gitobj.Reference, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	if !name.IsSafe() {
		return nil, gitobj.ErrReferenceNotFound
	}
	// Resolve only the requested ref. An unrelated broken ref or an in-flight
	// lock file must not prevent an explicitly selected history scan. This also
	// admits root pseudorefs such as ORIG_HEAD, which are not history roots.
	info, err := s.fs.Stat(name.String())
	if err == nil && !info.IsDir() {
		raw, err := readLimited(s.fs, name.String(), 1<<20)
		if err == nil && len(raw) > 0 {
			return s.parseRef(name.String(), strings.TrimSpace(raw))
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := s.loadPackedRefs(); err != nil {
		return nil, err
	}
	r := s.packedRefs[name]
	if r == nil {
		return nil, gitobj.ErrReferenceNotFound
	}
	return r, nil
}
func (s *objectStorage) IterReferences() (*gitobj.ReferenceIter, error) {
	if err := s.loadRefs(); err != nil {
		return nil, err
	}
	refs := make([]*gitobj.Reference, 0, len(s.refs))
	for _, r := range s.refs {
		refs = append(refs, r)
	}
	slices.SortFunc(refs, func(a, b *gitobj.Reference) int { return strings.Compare(a.Name().String(), b.Name().String()) })
	return gitobj.NewReferenceIter(refs), nil
}
