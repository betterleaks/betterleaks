package sources

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	objstore "github.com/ahrav/go-gitpack"

	"github.com/betterleaks/betterleaks/v2/internal/gitdiff"
	"github.com/betterleaks/betterleaks/v2/internal/logging"
)

// Git history engines. GitEngineAuto reads pack files in process through
// go-gitpack when the scan is a plain history scan and runs the git
// executable otherwise; GitEngineGit always runs git; GitEnginePack always
// reads pack files in process and reports an error for scans it cannot
// serve.
const (
	GitEngineAuto = "auto"
	GitEngineGit  = "git"
	GitEnginePack = "gitpack"
)

// validGitEngine reports whether engine names a known history engine; the
// empty string selects GitEngineAuto.
func validGitEngine(engine string) bool {
	switch engine {
	case "", GitEngineAuto, GitEngineGit, GitEnginePack:
		return true
	}
	return false
}

// packEngineReason explains why a scan cannot run in process, or "" when it
// can: the in-process engine serves the default history scan of a local
// repository (every ref, first-parent diffs, no git log options). Git log
// options, diff modes and the additional resources (commit messages, tag
// messages, reflogs) stay with the git executable.
func (s *Git) packEngineReason() string {
	switch {
	case s.Mode != GitHistory:
		return "diff modes require the git executable"
	case s.LogOpts != "":
		return "--log-opts requires the git executable"
	case len(s.Include) > 0:
		return "--include requires the git executable"
	}
	return ""
}

// InProcess reports whether a RepoPath history scan reads pack files in
// process. Validate reports the configuration errors usePackEngine returns.
func (s *Git) InProcess() bool {
	inProcess, err := s.usePackEngine()
	return err == nil && inProcess
}

// usePackEngine decides whether fragmentsFromRepo reads history in process.
func (s *Git) usePackEngine() (bool, error) {
	switch s.Engine {
	case "", GitEngineAuto:
		return s.packEngineReason() == "", nil
	case GitEngineGit:
		return false, nil
	case GitEnginePack:
		if reason := s.packEngineReason(); reason != "" {
			return false, fmt.Errorf("git engine %q: %s", GitEnginePack, reason)
		}
		return true, nil
	}
	return false, fmt.Errorf("unknown git engine %q (supported: auto, git, gitpack)", s.Engine)
}

// resolveGitDir returns the repository directory holding objects/ and refs/
// for repoPath: the path itself for a bare repository, its .git directory
// for a work tree, or the directory named by a .git file (linked work trees
// and submodules). A linked work tree's private directory names the shared
// repository in its commondir file, and that shared directory is returned,
// so the scan covers the refs of the whole repository. Relative entries
// resolve against the directory that holds them.
func resolveGitDir(repoPath string) (string, error) {
	clean := filepath.Clean(repoPath)
	dotGit := filepath.Join(clean, ".git")
	info, err := os.Stat(dotGit)
	var gitDir string
	switch {
	case err == nil && info.IsDir():
		gitDir = dotGit
	case err == nil:
		data, err := os.ReadFile(dotGit)
		if err != nil {
			return "", err
		}
		target, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "gitdir:")
		if !ok {
			return "", fmt.Errorf("%s: unrecognized .git file", clean)
		}
		target = strings.TrimSpace(target)
		if !filepath.IsAbs(target) {
			target = filepath.Join(clean, target)
		}
		gitDir = target
	case errors.Is(err, os.ErrNotExist):
		if _, err := os.Stat(filepath.Join(clean, "HEAD")); err != nil {
			return "", fmt.Errorf("%s: not a git repository", clean)
		}
		gitDir = clean
	default:
		return "", err
	}
	if data, err := os.ReadFile(filepath.Join(gitDir, "commondir")); err == nil {
		common := strings.TrimSpace(string(data))
		if !filepath.IsAbs(common) {
			common = filepath.Join(gitDir, common)
		}
		gitDir = filepath.Clean(common)
	}
	if st, err := os.Stat(filepath.Join(gitDir, "objects")); err != nil || !st.IsDir() {
		return "", fmt.Errorf("%s: not a git repository", clean)
	}
	return gitDir, nil
}

// Bounds for the scanner's materialized-object cache. The library default
// (256 MiB) suits multi-hundred-megabyte histories; a repository whose packs
// are smaller gains nothing from a cache larger than twice its packed size,
// and the budget is the largest component of the scan's live heap.
const (
	packObjectCacheMin = 32 << 20
	packObjectCacheMax = 256 << 20
)

// packRetainedBudget bounds the hunk bytes the deduplicating scanner holds
// ahead of the detector. The detector consumes fragments at a fraction of
// the scanner's production rate, so the bound sets the scan's peak heap.
const packRetainedBudget = 128 << 20

// packObjectCacheBudget sizes the scanner's object cache at twice the
// repository's packed bytes, within [packObjectCacheMin, packObjectCacheMax].
func packObjectCacheBudget(gitDir string) int {
	entries, err := os.ReadDir(filepath.Join(gitDir, "objects", "pack"))
	if err != nil {
		return packObjectCacheMax
	}
	var packed int64
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".pack") {
			continue
		}
		if info, err := e.Info(); err == nil {
			packed += info.Size()
		}
	}
	budget := 2 * packed
	switch {
	case budget < packObjectCacheMin:
		return packObjectCacheMin
	case budget > packObjectCacheMax:
		return packObjectCacheMax
	}
	return int(budget)
}

// gitHistoryReaders bounds the fragments a history scan has in flight at
// yield: the git engine runs at most this many history processes, each
// yielding serially, and the in-process engine admits the same number of
// concurrent yields from its workers.
func gitHistoryReaders() int {
	return min(max(runtime.GOMAXPROCS(0), 1), 4)
}

// fragmentsFromPack scans the repository's history in process: go-gitpack
// reads the pack files directly and streams every added hunk of every
// reachable commit, each commit diffed against its first parent (matching
// `git log -p --diff-merges=first-parent --all --full-history`), attributed
// to its commit through the scanner's metadata cache. The scanner's workers,
// one per processor, deliver hunks concurrently; yield admits
// gitHistoryReaders concurrent calls.
//
// With DedupLines the scanner emits each added line at its first
// introduction only, so a secret re-added, merged, or carried across
// branches is reported once; the plain engine reports every occurrence.
func (s *Git) fragmentsFromPack(ctx context.Context, yield FragmentsFunc) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	gitDir, err := resolveGitDir(s.RepoPath)
	if err != nil {
		return err
	}
	logger := logging.OrDiscard(s.Logger)
	opts := []objstore.ScannerOption{
		objstore.WithSkipMergeDiffs(false),
		objstore.WithHunkLineDedup(s.DedupLines),
		objstore.WithOffsetCacheBudget(packObjectCacheBudget(gitDir)),
		objstore.WithHunkDedupRetainedBudget(packRetainedBudget),
	}
	if s.Prefilter != nil {
		// The pair-level filter drops skipped paths before any blob is
		// diffed; the path is the only attribute the prefilter needs.
		skip := s.Prefilter
		opts = append(opts, objstore.WithHunkPathFilter(func(commit objstore.Hash, path string) bool {
			return skip(map[string]string{AttrPath: path})
		}))
	}
	scanner, err := objstore.NewHistoryScanner(gitDir, opts...)
	if err != nil {
		return fmt.Errorf("open repository %s: %w", s.RepoPath, err)
	}
	defer scanner.Close()
	logger.Debug("in-process git history scan", "git_dir", gitDir, "dedup_lines", s.DedupLines)

	attrs := &packCommitAttrs{scanner: scanner, source: s}
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		errMu    sync.Mutex
		yieldErr error
	)
	fail := func(err error) error {
		errMu.Lock()
		if yieldErr == nil {
			yieldErr = err
		}
		errMu.Unlock()
		cancel()
		return err
	}
	slots := make(chan struct{}, gitHistoryReaders())
	consume := yield
	yield = func(fragment Fragment, ferr error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case slots <- struct{}{}:
		}
		defer func() { <-slots }()
		return consume(fragment, ferr)
	}
	scanErr := scanner.DiffHistoryHunksFunc(func(h objstore.HunkAddition) error {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		commitAttrs, err := attrs.get(h.Commit())
		if err != nil {
			return fail(err)
		}
		if s.Prefilter != nil && s.Prefilter(commitAttrs) {
			logger.Log(ctx, logging.LevelTrace, "skipping diff entry: global prefilter", "commit", commitAttrs[AttrGitSHA], "path", h.Path())
			return nil
		}
		// Each attribute map is shared by every hunk of its commit, so the
		// per-path copy keeps the shared map immutable.
		fileAttrs := maps.Clone(commitAttrs)
		fileAttrs[AttrPath] = h.Path()
		if h.IsBinary() {
			if s.MaxArchiveDepth <= 0 || !isArchive(ctx, h.Path()) {
				return nil
			}
			lines := h.Lines()
			if len(lines) == 0 {
				return nil
			}
			if err := s.fragmentsFromPackArchive(ctx, h.Path(), strings.NewReader(lines[0]), fileAttrs, yield); err != nil {
				return fail(err)
			}
			return nil
		}
		if err := yield(Fragment{Raw: joinAddedLines(h.Lines()), StartLine: h.StartLine(), Attributes: fileAttrs}, nil); err != nil {
			return fail(err)
		}
		return nil
	})
	errMu.Lock()
	first := yieldErr
	errMu.Unlock()
	if err := parent.Err(); err != nil {
		return err
	}
	if first != nil {
		return first
	}
	if scanErr != nil {
		return fmt.Errorf("scan git history: %w", scanErr)
	}
	return nil
}

// joinAddedLines renders hunk lines the way the patch reader renders added
// lines: each line followed by its newline.
func joinAddedLines(lines []string) string {
	size := len(lines)
	for _, l := range lines {
		size += len(l)
	}
	var raw strings.Builder
	raw.Grow(size)
	for _, l := range lines {
		raw.WriteString(l)
		raw.WriteByte('\n')
	}
	return raw.String()
}

// fragmentsFromPackArchive scans a binary blob delivered by the pack engine
// as an archive, mirroring fragmentsFromArchive for the git engine.
func (s *Git) fragmentsFromPackArchive(ctx context.Context, path string, blob *strings.Reader, commitAttrs map[string]string, yield FragmentsFunc) error {
	file := File{
		Logger:          s.Logger,
		Content:         bufio.NewReader(blob),
		Path:            path,
		Attributes:      commitAttrs,
		MaxArchiveDepth: s.MaxArchiveDepth,
		Prefilter:       s.Prefilter,
	}
	return file.Fragments(ctx, yield)
}

// packCommitAttrs memoizes the per-commit attribute map every hunk of a
// commit shares; the maps are immutable after construction.
type packCommitAttrs struct {
	scanner *objstore.HistoryScanner
	source  *Git
	m       sync.Map // objstore.Hash -> map[string]string
}

func (c *packCommitAttrs) get(oid objstore.Hash) (map[string]string, error) {
	if v, ok := c.m.Load(oid); ok {
		return v.(map[string]string), nil
	}
	meta, err := c.scanner.GetCommitMetadata(oid)
	if err != nil {
		return nil, fmt.Errorf("read commit %s: %w", oid, err)
	}
	attrs := map[string]string{
		AttrGitSHA:     oid.String(),
		AttrGitMessage: gitdiff.FormatMessage(meta.Message),
		AttrResource:   ResourceGitPatchContent,
	}
	if c.source.RemoteURL != "" {
		attrs[AttrGitRemoteURL] = c.source.RemoteURL
		attrs[AttrGitPlatform] = c.source.Platform.String()
	}
	if !meta.Author.When.IsZero() {
		attrs[AttrGitDate] = meta.Author.When.UTC().Format(time.RFC3339)
	}
	if meta.Author.Name != "" || meta.Author.Email != "" {
		attrs[AttrGitAuthorName] = meta.Author.Name
		attrs[AttrGitAuthorEmail] = meta.Author.Email
	}
	v, _ := c.m.LoadOrStore(oid, attrs)
	return v.(map[string]string), nil
}

// remoteURLFromConfig reads the URL of the repository's default remote from
// its config file: remote.origin.url when origin is configured, otherwise the
// first remote.<name>.url entry. The second result is false when the
// repository or the entry is absent, in which case callers consult git,
// which also applies url.<base>.insteadOf rewrites.
func remoteURLFromConfig(repoPath string) (string, bool) {
	gitDir, err := resolveGitDir(repoPath)
	if err != nil {
		return "", false
	}
	f, err := os.Open(filepath.Join(gitDir, "config"))
	if err != nil {
		return "", false
	}
	defer f.Close()

	var (
		section string // remote name inside a [remote "name"] section, "" elsewhere
		first   string
		origin  string
	)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || line[0] == '#' || line[0] == ';':
			continue
		case line[0] == '[':
			section = ""
			if rest, ok := strings.CutPrefix(line, `[remote "`); ok {
				if name, _, ok := strings.Cut(rest, `"`); ok {
					section = name
				}
			}
			continue
		case section == "":
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "url" {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if section == "origin" && origin == "" {
			origin = value
		}
		if first == "" {
			first = value
		}
	}
	if origin != "" {
		return origin, true
	}
	return first, first != ""
}
