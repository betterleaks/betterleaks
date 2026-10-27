package gogit

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/v2/internal/gitobj"
	"github.com/betterleaks/betterleaks/v2/sources"
)

// Reflogs are local journals, not Git objects. Stream them without keeping a
// reverse index or sorting by timestamps. Every entry's message is scanned.
// When roots is set, every recorded old and new commit becomes a history root;
// the walk's visited set deduplicates them with ref history. Old IDs matter: a
// reset can discard its old tip.
func (s *Source) reflogs(ctx context.Context, store *objectStorage, roots *history, yield sources.FragmentsFunc) error {
	cfg, err := store.Config()
	if err != nil {
		return err
	}
	hashLength := gitobj.FromObjectFormat(cfg.Extensions.ObjectFormat).Size() * 2
	fs := store.Filesystem().(readOnlyFS)
	root, err := os.OpenRoot(fs.objectRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	visit := func(root *os.Root, name, ref string) error {
		f, err := root.Open(name)
		if err != nil {
			return err
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		// Bound a single untrusted entry; total log length is streamed.
		scanner.Buffer(make([]byte, 4096), maxReflogRecord)
		// Require complete records. Scanner's default SplitLines accepts a
		// truncated final record, which could silently lose part of a message.
		scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
			if atEOF && len(data) > 0 && !bytes.ContainsRune(data, '\n') {
				return 0, nil, errors.New("unterminated reflog entry")
			}
			return bufio.ScanLines(data, atEOF)
		})
		for line := 1; scanner.Scan(); line++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			e, err := parseReflog(scanner.Text(), hashLength)
			if err != nil {
				return fmt.Errorf("reflog %s line %d: %w", name, line, err)
			}
			attrs := map[string]string{
				sources.AttrResource:            sources.ResourceGitReflogMessage,
				sources.AttrGitReflogRef:        ref,
				sources.AttrGitReflogActorName:  e.name,
				sources.AttrGitReflogActorEmail: e.email,
				sources.AttrGitReflogDate:       e.when.UTC().Format(time.RFC3339),
				sources.AttrGitReflogOldSHA:     e.old.String(),
				sources.AttrGitReflogNewSHA:     e.new.String(),
				sources.AttrGitReflogLog:        name,
				sources.AttrGitReflogLine:       strconv.Itoa(line),
			}
			if s.Prefilter == nil || !s.Prefilter(attrs) {
				if err := yield(sources.Fragment{Raw: e.message, StartLine: 1, Attributes: attrs}, nil); err != nil {
					return err
				}
			}
			if roots != nil {
				for _, id := range []gitobj.Hash{e.old, e.new} {
					if id.IsZero() {
						continue
					}
					if err := roots.tip(ctx, id); err != nil {
						return fmt.Errorf("reflog %s line %d: %w", name, line, err)
					}
				}
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("reflog %s: %w", name, err)
		}
		return ctx.Err()
	}
	if err := walkReflogs(ctx, root, "logs", "", 0, visit); err != nil {
		return err
	}
	// Each linked worktree has a separate HEAD journal and may have refs in
	// per-worktree namespaces. Read every registered worktree, like git reflog
	// --all, rather than depending on which worktree the caller selected.
	if info, err := root.Lstat("worktrees"); err == nil {
		if !info.IsDir() {
			return errors.New("git worktrees path is not a directory")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	worktrees, err := root.Open("worktrees")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		defer worktrees.Close()
		for {
			entries, err := worktrees.ReadDir(256)
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			for _, entry := range entries {
				if !entry.IsDir() {
					return errors.New("non-directory entry in Git worktrees directory")
				}
				name := filepath.Join("worktrees", entry.Name(), "logs")
				if err := walkReflogs(ctx, root, name, "", 0, visit); err != nil {
					return err
				}
			}
			if errors.Is(err, io.EOF) {
				break
			}
		}
	}
	// A manually configured commondir can live outside the standard worktrees
	// layout. Include that caller-selected Git directory without reading it twice.
	rel, err := filepath.Rel(fs.objectRoot, fs.Root())
	if err != nil {
		return err
	}
	if rel != "." && filepath.Dir(rel) != "worktrees" {
		local, err := os.OpenRoot(fs.Root())
		if err != nil {
			return err
		}
		defer local.Close()
		return walkReflogs(ctx, local, "logs", "", 0, visit)
	}
	return ctx.Err()
}

// Confine reads to the Git directory. Never follow journal symlinks or open
// device nodes/FIFOs. Read directories in batches instead of retaining all logs.
func walkReflogs(ctx context.Context, root *os.Root, name, ref string, depth int, visit func(*os.Root, string, string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth > maxReflogDepth {
		return fmt.Errorf("reflog directory nesting exceeds %d levels", maxReflogDepth)
	}
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) && depth == 0 {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode().IsRegular() {
		if depth == 0 {
			return fmt.Errorf("reflog directory %s is a file", name)
		}
		return visit(root, name, ref)
	}
	if !info.IsDir() {
		return fmt.Errorf("reflog path %s is not a regular file or directory", name)
	}
	dir, err := root.Open(name)
	if err != nil {
		return err
	}
	defer dir.Close()
	for {
		entries, err := dir.ReadDir(256)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		for _, entry := range entries {
			childRef := entry.Name()
			if ref != "" {
				childRef = ref + "/" + childRef
			}
			if err := walkReflogs(ctx, root, filepath.Join(name, entry.Name()), childRef, depth+1, visit); err != nil {
				return err
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

type reflogEntry struct {
	old, new             gitobj.Hash
	name, email, message string
	when                 time.Time
}

func parseReflog(line string, hashLength int) (reflogEntry, error) {
	var e reflogEntry
	bad := errors.New("malformed reflog entry") // Never echo secret-bearing input.
	header, message, _ := strings.Cut(line, "\t")
	// Git permits records without a message (and without the tab).
	fields := strings.SplitN(header, " ", 3)
	if len(fields) != 3 {
		return e, bad
	}
	for _, id := range fields[:2] {
		if len(id) != hashLength || !gitobj.IsHash(id) {
			return e, bad
		}
	}
	emailEnd := strings.LastIndex(fields[2], "> ")
	emailStart := strings.LastIndex(fields[2], " <")
	if emailStart < 0 || emailEnd <= emailStart+1 {
		return e, bad
	}
	stamp := fields[2][emailEnd+2:]
	// The zone is part of the recorded identity time, not a commit timestamp.
	zone := stamp[max(0, len(stamp)-5):]
	_, err := time.Parse("-0700", zone)
	if err != nil || len(stamp) < 7 || stamp[len(stamp)-6] != ' ' || zone[1:3] >= "24" || zone[3:] >= "60" {
		return e, bad
	}
	seconds, err := strconv.ParseInt(stamp[:len(stamp)-6], 10, 64)
	if err != nil {
		return e, bad
	}
	e.old, e.new = gitobj.NewHash(fields[0]), gitobj.NewHash(fields[1])
	e.name, e.email, e.message = fields[2][:emailStart], fields[2][emailStart+2:emailEnd], message
	e.when = time.Unix(seconds, 0).UTC()
	if e.when.Year() < 0 || e.when.Year() > 9999 {
		return reflogEntry{}, bad
	}
	return e, nil
}
