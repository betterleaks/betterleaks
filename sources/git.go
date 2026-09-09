package sources

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/sync/errgroup"

	"github.com/betterleaks/betterleaks/v2/internal/gitdiff"
	"github.com/betterleaks/betterleaks/v2/sources/scm"
)

// Git is a source for yielding fragments from a git repo
type Git struct {
	// Logger receives source diagnostics. A nil logger disables logging.
	Logger *slog.Logger
	// Cmd scans an already-started Git command. When Cmd is nil, Fragments
	// starts a history scan for RepoPath.
	Cmd      *GitCmd
	RepoPath string
	LogOpts  string
	// Include adds resources to the default patch scan. Supported values:
	// commit-messages, tag-messages. Additional resources require RepoPath rather than Cmd.
	Include []string

	ShouldSkip      SkipFunc
	Platform        scm.Platform
	RemoteURL       string
	MaxArchiveDepth int
	// Jobs bounds concurrent Git history processes for RepoPath scans and
	// fragment processing for an explicitly supplied Cmd. Zero is automatic.
	Jobs int

	budget   *jobBudget
	jobOwned bool
}

const (
	GitResourceTypeCommitMessages = "commit-messages"
	GitResourceTypeTagMessages    = "tag-messages"
)

// Validate checks additional Git resource selections before starting a scan.
func (s *Git) Validate() error {
	for _, name := range s.Include {
		if name != GitResourceTypeCommitMessages && name != GitResourceTypeTagMessages {
			return fmt.Errorf("unknown Git resource type %q (supported: commit-messages, tag-messages)", name)
		}
	}
	if len(s.Include) > 0 && s.Cmd != nil {
		return errors.New("additional Git resources require RepoPath rather than Cmd")
	}
	return nil
}

// Fragments yields fragments from a git repo
func (s *Git) Fragments(ctx context.Context, yield FragmentsFunc) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if s.Cmd == nil {
		if s.RepoPath == "" {
			return errors.New("git source requires Cmd or RepoPath")
		}
		if err := s.fragmentsFromRepo(ctx, yield); err != nil {
			return err
		}
		if slices.Contains(s.Include, GitResourceTypeTagMessages) {
			return s.budget.run(ctx, func() error {
				return s.fragmentsFromTagMessages(ctx, yield)
			})
		}
		return nil
	}
	return s.fragmentsFromCmd(ctx, yield)
}

// fragmentsFromRepo partitions Git history across at most GOMAXPROCS processes.
// Each process consumes fragments serially; the detector provides the other
// half of the bounded jobs pipeline.
func (s *Git) fragmentsFromRepo(ctx context.Context, yield FragmentsFunc) error {
	jobs := jobsWithinBudget(s.Jobs, automaticGitJobs(), s.budget)
	historyJobs := min(jobs, automaticJobs())

	repoSource := *s
	repoSource.Jobs = jobs

	includeMessages := slices.Contains(s.Include, GitResourceTypeCommitMessages)
	if historyJobs <= 1 && !includeMessages {
		return s.budget.run(ctx, func() error {
			return repoSource.runFullHistory(ctx, yield)
		})
	}

	var commits []string
	err := s.budget.run(ctx, func() error {
		var err error
		commits, err = listCommits(ctx, s.RepoPath, s.LogOpts)
		return err
	})
	if err != nil {
		return fmt.Errorf("list commits: %w", err)
	}
	if len(commits) == 0 {
		return nil
	}

	workers := min(historyJobs, len(commits))
	if workers == 1 && !includeMessages {
		return s.budget.run(ctx, func() error {
			return repoSource.runFullHistory(ctx, yield)
		})
	}

	chunkSize := (len(commits) + workers - 1) / workers
	loggerOrDiscard(s.Logger).Debug("parallel git scan", "commits", len(commits), "workers", workers, "chunk_size", chunkSize)

	g, groupCtx := errgroup.WithContext(ctx)
	for i := range workers {
		start := i * chunkSize
		if start >= len(commits) {
			break
		}
		end := min(start+chunkSize, len(commits))
		chunk := commits[start:end]
		g.Go(func() error {
			return s.budget.run(groupCtx, func() error {
				return repoSource.runHistoryChunk(groupCtx, yield, chunk)
			})
		})
	}
	return g.Wait()
}

func (s *Git) runFullHistory(ctx context.Context, yield FragmentsFunc) error {
	cmd, err := NewGitLogCmdContext(ctx, s.RepoPath, s.LogOpts, WithGitCmdLogger(s.Logger), withGitStreaming())
	if err != nil {
		return err
	}
	return s.runGitCmd(ctx, yield, cmd)
}

func (s *Git) runHistoryChunk(ctx context.Context, yield FragmentsFunc, commits []string) error {
	cmd, err := newGitLogCommitsCmd(ctx, s.RepoPath, commits, s.Logger)
	if err != nil {
		return err
	}
	if err := s.runGitCmd(ctx, yield, cmd); err != nil {
		return err
	}
	if slices.Contains(s.Include, GitResourceTypeCommitMessages) {
		return s.fragmentsFromCommitMessages(ctx, commits, yield)
	}
	return nil
}

// fragmentsFromCommitMessages reads one commit object per selected revision.
// Batch framing preserves message bytes, including blank lines and text that
// resembles a patch header. The caller already owns a source job, so this does
// not multiply the Git process budget.
func (s *Git) fragmentsFromCommitMessages(ctx context.Context, commits []string, yield FragmentsFunc) (scanErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", s.RepoPath, "cat-file", "--batch")
	cmd.Env = gitConfigIsolationEnv()
	cmd.Stdin = strings.NewReader(strings.Join(commits, "\n") + "\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() {
		if scanErr != nil {
			cancel()
		}
		waitErr := cmd.Wait()
		if scanErr == nil && waitErr != nil {
			scanErr = fmt.Errorf("read Git commit messages: %w", waitErr)
		}
		if scanErr != nil && stderr.Len() > 0 {
			scanErr = fmt.Errorf("%w: %s", scanErr, strings.TrimSpace(stderr.String()))
		}
	}()

	reader := bufio.NewReader(stdout)
	for range commits {
		if err := ctx.Err(); err != nil {
			return err
		}
		fragment, err := readGitCommitMessage(reader)
		if err != nil {
			return fmt.Errorf("read Git commit message: %w", err)
		}
		if s.RemoteURL != "" {
			fragment.SetAttr(AttrGitRemoteURL, s.RemoteURL)
			fragment.SetAttr(AttrGitPlatform, s.Platform.String())
		}
		if fragment.Raw == "" || shouldSkipAttrs(s.ShouldSkip, fragment.Attributes) {
			continue
		}
		if err := yield(fragment, nil); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func readGitCommitMessage(reader *bufio.Reader) (Fragment, error) {
	oid, data, err := readGitMessageObject(reader, "commit")
	if err != nil {
		return Fragment{}, err
	}
	headers, message, ok := strings.Cut(string(data), "\n\n")
	if !ok {
		return Fragment{}, fmt.Errorf("commit %s has no message separator", oid)
	}
	attrs := map[string]string{
		AttrResource:   ResourceGitCommitMessage,
		AttrGitSHA:     oid,
		AttrGitMessage: message,
	}
	for _, line := range strings.Split(headers, "\n") {
		author, ok := strings.CutPrefix(line, "author ")
		if !ok {
			continue
		}
		if err := setGitMessageIdentity(attrs, author, AttrGitAuthorName, AttrGitAuthorEmail); err != nil {
			return Fragment{}, fmt.Errorf("parse commit %s author: %w", oid, err)
		}
		break
	}
	return Fragment{Raw: message, StartLine: 1, Attributes: attrs}, nil
}

// readGitMessageObject uses cat-file's byte counts rather than delimiters in
// message text, so multiline messages and embedded NUL bytes remain intact.
func readGitMessageObject(reader *bufio.Reader, objectType string) (string, []byte, error) {
	header, err := reader.ReadString('\n')
	if err != nil {
		return "", nil, err
	}
	fields := strings.Fields(header)
	if len(fields) != 3 || fields[1] != objectType {
		return "", nil, fmt.Errorf("expected a %s object, received %q", objectType, strings.TrimSpace(header))
	}
	size, err := strconv.Atoi(fields[2])
	if err != nil || size < 0 {
		return "", nil, fmt.Errorf("invalid %s object size %q", objectType, fields[2])
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return "", nil, err
	}
	separator, err := reader.ReadByte()
	if err != nil {
		return "", nil, err
	}
	if separator != '\n' {
		return "", nil, fmt.Errorf("invalid %s object separator", objectType)
	}
	return fields[0], data, nil
}

func setGitMessageIdentity(attrs map[string]string, value, nameKey, emailKey string) error {
	end := strings.LastIndex(value, "> ")
	if end < 0 {
		return fmt.Errorf("invalid identity")
	}
	identity, err := gitdiff.ParsePatchIdentity(value[:end+1])
	if err != nil {
		return err
	}
	date, err := gitdiff.ParsePatchDate(value[end+2:])
	if err != nil {
		return err
	}
	attrs[nameKey] = identity.Name
	attrs[emailKey] = identity.Email
	attrs[AttrGitDate] = date.UTC().Format(time.RFC3339)
	return nil
}

type gitTagRef struct {
	oid string
	ref string
}

// fragmentsFromTagMessages scans each distinct annotation reachable from local
// tag refs. Tags select their own objects independently of commit LogOpts. The
// caller holds a source job; one cat-file process handles all tag objects,
// including annotations reached through other annotated tags.
func (s *Git) fragmentsFromTagMessages(ctx context.Context, yield FragmentsFunc) (scanErr error) {
	list := exec.CommandContext(ctx, "git", "-C", s.RepoPath, "for-each-ref",
		"--format=%(objecttype) %(objectname) %(refname)", "refs/tags/")
	list.Env = gitConfigIsolationEnv()
	var stderr bytes.Buffer
	list.Stderr = &stderr
	out, err := list.Output()
	if err != nil {
		return fmt.Errorf("list Git tags: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var tags []gitTagRef
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "tag" {
			tags = append(tags, gitTagRef{oid: fields[1], ref: fields[2]})
		}
	}
	if len(tags) == 0 {
		return ctx.Err()
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", s.RepoPath, "cat-file", "--batch")
	cmd.Env = gitConfigIsolationEnv()
	stderr.Reset()
	cmd.Stderr = &stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	defer stdin.Close()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() {
		_ = stdin.Close()
		if scanErr != nil {
			cancel()
		}
		waitErr := cmd.Wait()
		if scanErr == nil && waitErr != nil {
			scanErr = fmt.Errorf("read Git tag messages: %w", waitErr)
		}
		if scanErr != nil && stderr.Len() > 0 {
			scanErr = fmt.Errorf("%w: %s", scanErr, strings.TrimSpace(stderr.String()))
		}
	}()

	reader := bufio.NewReader(stdout)
	seen := make(map[string]bool, len(tags))
	for i := 0; i < len(tags); i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		tag := tags[i]
		if seen[tag.oid] {
			continue
		}
		seen[tag.oid] = true
		if _, err := fmt.Fprintln(stdin, tag.oid); err != nil {
			return fmt.Errorf("request Git tag object: %w", err)
		}
		fragment, nestedTag, err := readGitTagMessage(reader)
		if err != nil {
			return fmt.Errorf("read Git tag message: %w", err)
		}
		if nestedTag != "" {
			tags = append(tags, gitTagRef{oid: nestedTag})
		}
		if tag.ref != "" {
			fragment.SetAttr(AttrGitTagRef, tag.ref)
		}
		if s.RemoteURL != "" {
			fragment.SetAttr(AttrGitRemoteURL, s.RemoteURL)
			fragment.SetAttr(AttrGitPlatform, s.Platform.String())
		}
		if fragment.Raw == "" || shouldSkipAttrs(s.ShouldSkip, fragment.Attributes) {
			continue
		}
		if err := yield(fragment, nil); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// readGitTagMessage returns a nested tag's OID when the annotation tags another
// tag. Non-commit targets are valid, so attribution uses the tag object itself.
func readGitTagMessage(reader *bufio.Reader) (Fragment, string, error) {
	oid, data, err := readGitMessageObject(reader, "tag")
	if err != nil {
		return Fragment{}, "", err
	}
	headers, message, ok := strings.Cut(string(data), "\n\n")
	if !ok {
		return Fragment{}, "", fmt.Errorf("tag %s has no message separator", oid)
	}
	attrs := map[string]string{
		AttrResource:   ResourceGitTagMessage,
		AttrGitSHA:     oid,
		AttrGitMessage: message,
	}
	var target, targetType string
	for line := range strings.SplitSeq(headers, "\n") {
		key, value, _ := strings.Cut(line, " ")
		switch key {
		case "object":
			target = value
		case "type":
			targetType = value
		case "tag":
			attrs[AttrGitTagName] = value
		case "tagger":
			if err := setGitMessageIdentity(attrs, value, AttrGitTaggerName, AttrGitTaggerEmail); err != nil {
				return Fragment{}, "", fmt.Errorf("parse tag %s tagger: %w", oid, err)
			}
		}
	}
	if target == "" || targetType == "" || attrs[AttrGitTagName] == "" {
		return Fragment{}, "", fmt.Errorf("tag %s has incomplete headers", oid)
	}
	var nestedTag string
	if targetType == "tag" {
		nestedTag = target
	}
	return Fragment{Raw: message, StartLine: 1, Attributes: attrs}, nestedTag, nil
}

func (s *Git) runGitCmd(ctx context.Context, yield FragmentsFunc, cmd *GitCmd) error {
	commandSource := *s
	commandSource.Cmd = cmd
	commandSource.RepoPath = ""
	commandSource.LogOpts = ""
	commandSource.Jobs = 1
	commandSource.jobOwned = true
	return commandSource.fragmentsFromCmd(ctx, yield)
}

func (s *Git) fragmentsFromCmd(ctx context.Context, yield FragmentsFunc) error {
	if s.Cmd.stdout != nil {
		return s.fragmentsFromStream(ctx, yield)
	}
	return s.fragmentsFromDiffFiles(ctx, yield)
}

func (s *Git) fragmentsFromStream(ctx context.Context, yield FragmentsFunc) error {
	readErr := readGitPatch(ctx, s.Cmd.stdout, func(file *gitdiff.File) (gitHunkFunc, error) {
		if file.IsDelete {
			return nil, nil
		}
		attrs := s.gitAttributes(file)
		if shouldSkipAttrs(s.ShouldSkip, attrs) {
			logTrace(ctx, s.Logger, "skipping diff entry: global prefilter", "commit", attrs[AttrGitSHA], "path", file.NewName)
			return nil, nil
		}
		if file.IsBinary {
			if s.MaxArchiveDepth <= 0 || !isArchive(ctx, file.NewName) {
				return nil, nil
			}
			return nil, s.fragmentsFromArchive(ctx, file.NewName, attrs, yield)
		}
		return func(raw string, startLine int) error {
			return yield(Fragment{Raw: raw, StartLine: startLine, Attributes: attrs}, nil)
		}, nil
	})
	if readErr == nil {
		readErr = ctx.Err()
	}
	stopped := false
	if readErr != nil {
		cancelErr := s.Cmd.cancel()
		stopped = cancelErr == nil
		readErr = errors.Join(readErr, cancelErr)
	}
	for err := range s.Cmd.ErrCh() {
		readErr = errors.Join(readErr, err)
	}
	waitErr := s.Cmd.Wait()
	var exitErr *exec.ExitError
	if stopped && errors.As(waitErr, &exitErr) && exitErr.ExitCode() == -1 {
		// Killing Git is cleanup after the original failure. Its signal exit
		// adds no diagnostic value; retain parser, callback, and stderr errors.
		waitErr = nil
	}
	return errors.Join(readErr, waitErr)
}

// fragmentsFromDiffFiles supports callers using the complete DiffFilesCh API.
func (s *Git) fragmentsFromDiffFiles(ctx context.Context, yield FragmentsFunc) error {
	defer func() {
		if err := s.Cmd.Wait(); err != nil {
			loggerOrDiscard(s.Logger).Debug("command aborted", "error", err, "command", s.Cmd.String())
		}
	}()

	g, groupCtx := errgroup.WithContext(ctx)
	jobs := jobsWithinBudget(s.Jobs, automaticJobs(), s.budget)
	g.SetLimit(jobs)

	var (
		diffFilesCh = s.Cmd.DiffFilesCh()
		errCh       = s.Cmd.ErrCh()
	)
	finish := func(producerErr error) error {
		if groupCtx.Err() != nil {
			producerErr = errors.Join(producerErr, s.Cmd.cancel())
		}
		producerErr = errors.Join(producerErr, drainGitOutput(diffFilesCh, errCh))
		return waitForGitWorkers(g, groupCtx, producerErr)
	}

	// loop to range over both DiffFiles (stdout) and ErrCh (stderr)
	for diffFilesCh != nil || errCh != nil {
		select {
		case <-groupCtx.Done():
			return finish(nil)
		case gitdiffFile, open := <-diffFilesCh:
			if !open {
				diffFilesCh = nil
				break
			}
			if groupCtx.Err() != nil {
				return finish(nil)
			}

			if gitdiffFile.IsDelete {
				continue
			}

			// skip non-archive binary files
			yieldAsArchive := false
			if gitdiffFile.IsBinary {
				if s.MaxArchiveDepth <= 0 || !isArchive(ctx, gitdiffFile.NewName) {
					continue
				}
				yieldAsArchive = true
			}

			// Build commit attributes and check the prefilter before
			// allocating goroutines or fragment memory.
			commitAttrs := s.gitAttributes(gitdiffFile)
			commitSHA := commitAttrs[AttrGitSHA]
			if shouldSkipAttrs(s.ShouldSkip, commitAttrs) {
				logTrace(groupCtx, s.Logger, "skipping diff entry: global prefilter", "commit", commitSHA, "path", gitdiffFile.NewName)
				continue
			}

			g.Go(func() error {
				run := func() error {
					if groupCtx.Err() != nil {
						return nil
					}
					if yieldAsArchive {
						return s.fragmentsFromArchive(groupCtx, gitdiffFile.NewName, commitAttrs, yield)
					}

					for _, textFragment := range gitdiffFile.TextFragments {
						if textFragment == nil {
							return nil
						}
						fragment := Fragment{
							Raw:        addedGitLines(textFragment),
							StartLine:  int(textFragment.NewPosition),
							Attributes: commitAttrs,
						}

						if err := yield(fragment, nil); err != nil {
							return err
						}
					}

					return nil
				}
				if s.jobOwned {
					return run()
				}
				return s.budget.run(groupCtx, run)
			})
		case err, open := <-errCh:
			if !open {
				errCh = nil
				break
			}
			if groupCtx.Err() != nil {
				return finish(err)
			}

			return finish(yield(Fragment{}, err))
		}
	}

	return waitForGitWorkers(g, groupCtx, nil)
}

func waitForGitWorkers(g *errgroup.Group, groupCtx context.Context, producerErr error) error {
	groupErr := groupCtx.Err()
	workerErr := g.Wait()
	if workerErr != nil {
		return errors.Join(producerErr, workerErr)
	}
	return errors.Join(producerErr, groupErr)
}

func drainGitOutput(diffFilesCh <-chan *gitdiff.File, errCh <-chan error) error {
	var producerErr error
	for diffFilesCh != nil || errCh != nil {
		select {
		case _, open := <-diffFilesCh:
			if !open {
				diffFilesCh = nil
			}
		case err, open := <-errCh:
			if !open {
				errCh = nil
				continue
			}
			producerErr = errors.Join(producerErr, err)
		}
	}
	return producerErr
}

func (s *Git) fragmentsFromArchive(ctx context.Context, path string, commitAttrs map[string]string, yield FragmentsFunc) error {
	blob, err := s.Cmd.NewBlobReaderContext(ctx, commitAttrs[AttrGitSHA], path)
	if err != nil {
		loggerOrDiscard(s.Logger).Error("could not read archive blob", "error", err)
		return nil
	}
	file := File{
		Logger:          s.Logger,
		Content:         blob,
		Path:            path,
		MaxArchiveDepth: s.MaxArchiveDepth,
		ShouldSkip:      s.ShouldSkip,
	}
	err = file.Fragments(ctx, func(fragment Fragment, err error) error {
		attrs := maps.Clone(commitAttrs)
		maps.Copy(attrs, fragment.Attributes)
		fragment.Attributes = attrs
		return yield(fragment, err)
	})
	if closeErr := blob.Close(); closeErr != nil {
		loggerOrDiscard(s.Logger).Debug("blobReader.Close() returned an error", "error", closeErr)
	}
	return err
}

func (s *Git) gitAttributes(file *gitdiff.File) map[string]string {
	attrs := map[string]string{AttrPath: file.NewName}
	if patch := file.PatchHeader; patch != nil {
		attrs[AttrGitSHA] = patch.SHA
		attrs[AttrGitMessage] = patch.Message()
		attrs[AttrResource] = ResourceGitPatchContent
		if s.RemoteURL != "" {
			attrs[AttrGitRemoteURL] = s.RemoteURL
			attrs[AttrGitPlatform] = s.Platform.String()
		}
		if !patch.AuthorDate.IsZero() {
			attrs[AttrGitDate] = patch.AuthorDate.UTC().Format(time.RFC3339)
		}
		if patch.Author != nil {
			attrs[AttrGitAuthorName] = patch.Author.Name
			attrs[AttrGitAuthorEmail] = patch.Author.Email
		}
	}
	return attrs
}

// GitCmd helps to work with Git's output.
type GitCmd struct {
	cmd         *exec.Cmd
	diffFilesCh <-chan *gitdiff.File
	errCh       <-chan error
	repoPath    string
	stdout      io.Reader // internal history scans consume patches without line objects
}

type gitCmdOptions struct {
	logger *slog.Logger
	stream bool
}

// Internal scans use the streaming reader; the public DiffFilesCh API retains
// the complete gitdiff.File representation for callers that need it.
func withGitStreaming() GitCmdOption {
	return GitCmdOption{apply: func(options *gitCmdOptions) { options.stream = true }}
}

// GitCmdOption configures a Git command before it starts. Options are created
// by the WithGitCmd... functions in this package.
type GitCmdOption struct {
	apply func(*gitCmdOptions)
}

// WithGitCmdLogger directs Git command diagnostics to logger. A nil logger
// disables logging.
func WithGitCmdLogger(logger *slog.Logger) GitCmdOption {
	return GitCmdOption{apply: func(options *gitCmdOptions) {
		options.logger = loggerOrDiscard(logger)
	}}
}

func resolveGitCmdOptions(options []GitCmdOption) gitCmdOptions {
	resolved := gitCmdOptions{logger: discardLogger}
	for _, option := range options {
		if option.apply != nil {
			option.apply(&resolved)
		}
	}
	return resolved
}

// gitConfigIsolationEnv contains the standard Git configuration isolation environment variables.
// These settings prevent Git from reading user or system configuration files.
func gitConfigIsolationEnv() []string {
	var nullDevice string
	if runtime.GOOS == "windows" {
		nullDevice = "NUL"
	} else {
		nullDevice = "/dev/null"
	}
	overrides := map[string]string{
		"GIT_CONFIG_GLOBAL":      nullDevice,
		"GIT_CONFIG_NOSYSTEM":    "1",
		"GIT_CONFIG_SYSTEM":      nullDevice,
		"GIT_NO_REPLACE_OBJECTS": "1",
		"GIT_TERMINAL_PROMPT":    "0",
	}

	env := os.Environ()
	// Replace or append each override key.
	for i, e := range env {
		for k, v := range overrides {
			if strings.HasPrefix(e, k+"=") {
				env[i] = k + "=" + v
				delete(overrides, k)
			}
		}
	}
	for k, v := range overrides {
		env = append(env, k+"="+v)
	}
	return env
}

// blobReader provides a ReadCloser interface git cat-file blob to fetch
// a blob from a repo
type blobReader struct {
	io.ReadCloser
	cmd *exec.Cmd
}

// Close closes the underlying reader and then waits for the command to complete,
// releasing its resources.
func (br *blobReader) Close() error {
	// Discard the remaining data from the pipe to avoid blocking
	_, drainErr := io.Copy(io.Discard, br)
	// Close the pipe (should signal the command to stop if it hasn't already)
	closeErr := br.ReadCloser.Close()
	// Wait to prevent zombie processes.
	waitErr := br.cmd.Wait()
	// Return the first error encountered
	if drainErr != nil {
		return drainErr
	}
	if closeErr != nil {
		return closeErr
	}
	return waitErr
}

// NewGitLogCmd starts a Git history command. Callers must drain DiffFilesCh
// and ErrCh before calling Wait to release resources.
//
// Deprecated: use NewGitLogCmdContext instead.
func NewGitLogCmd(source string, logOpts string) (*GitCmd, error) {
	return NewGitLogCmdContext(context.Background(), source, logOpts)
}

// NewGitLogCmdContext is the same as NewGitLogCmd but supports passing in a
// context to use for timeouts
func NewGitLogCmdContext(ctx context.Context, source string, logOpts string, options ...GitCmdOption) (*GitCmd, error) {
	settings := resolveGitCmdOptions(options)
	sourceClean := filepath.Clean(source)
	var cmd *exec.Cmd
	if logOpts != "" {
		args := []string{"-C", sourceClean, "log", "-p", "-U0"}

		userArgs, err := splitGitLogOpts(logOpts)
		if err != nil {
			return nil, fmt.Errorf("invalid --log-opts: %w", err)
		}

		args = append(args, userArgs...)
		cmd = exec.CommandContext(ctx, "git", args...)
	} else {
		cmd = exec.CommandContext(ctx, "git", "-C", sourceClean, "log", "-p", "-U0",
			"--full-history", "--all", "--diff-filter=tuxdb")
	}
	return startGitCmd(cmd, sourceClean, settings)
}

// splitGitLogOpts parses user-provided --log-opts with a small shell-inspired
// tokenizer.
//
// Supported behavior:
//   - whitespace splits arguments unless inside quotes
//   - single and double quotes group text and are removed from output
//   - backslash escapes the next rune outside single quotes
//   - unmatched quote or trailing backslash returns an error
//
// This is intentionally not a full shell parser: no variable expansion,
// command substitution, glob expansion, or other shell features. Also, a
// standalone empty quoted token (for example "") is currently dropped.
func splitGitLogOpts(input string) ([]string, error) {
	var (
		args     []string
		curr     strings.Builder
		inSingle bool
		inDouble bool
		escaped  bool
	)

	flush := func() {
		if curr.Len() == 0 {
			return
		}
		args = append(args, curr.String())
		curr.Reset()
	}

	for _, r := range input {
		switch {
		case escaped:
			curr.WriteRune(r)
			escaped = false
		case r == '\\' && !inSingle:
			escaped = true
		case r == '\'' && !inDouble:
			inSingle = !inSingle
		case r == '"' && !inSingle:
			inDouble = !inDouble
		case unicode.IsSpace(r) && !inSingle && !inDouble:
			flush()
		default:
			curr.WriteRune(r)
		}
	}

	if escaped {
		return nil, errors.New("unterminated escape in --log-opts")
	}
	if inSingle || inDouble {
		return nil, errors.New("unterminated quote in --log-opts")
	}

	flush()
	return args, nil
}

// NewGitDiffCmd starts a Git diff command. Callers must drain DiffFilesCh
// and ErrCh before calling Wait to release resources.
//
// Deprecated: use NewGitDiffCmdContext instead.
func NewGitDiffCmd(source string, staged bool) (*GitCmd, error) {
	return NewGitDiffCmdContext(context.Background(), source, staged)
}

// NewGitDiffCmdContext is the same as NewGitDiffCmd but supports passing in a
// context to use for timeouts
func NewGitDiffCmdContext(ctx context.Context, source string, staged bool, options ...GitCmdOption) (*GitCmd, error) {
	settings := resolveGitCmdOptions(options)
	sourceClean := filepath.Clean(source)
	var cmd *exec.Cmd
	cmd = exec.CommandContext(ctx, "git", "-C", sourceClean, "diff", "-U0", "--no-ext-diff", ".")
	if staged {
		cmd = exec.CommandContext(ctx, "git", "-C", sourceClean, "diff", "-U0", "--no-ext-diff",
			"--staged", ".")
	}
	return startGitCmd(cmd, sourceClean, settings)
}

// startGitCmd starts a patch-producing command and selects its output reader.
func startGitCmd(cmd *exec.Cmd, repoPath string, settings gitCmdOptions) (*GitCmd, error) {
	cmd.Env = gitConfigIsolationEnv()

	settings.logger.Debug("executing git command", "command", cmd.String())

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	errCh := make(chan error)
	go listenForStdErr(stderr, errCh, settings.logger)

	if settings.stream {
		return &GitCmd{cmd: cmd, stdout: stdout, errCh: errCh, repoPath: repoPath}, nil
	}

	gitdiffFiles, err := gitdiff.Parse(stdout)
	if err != nil {
		return nil, err
	}

	return &GitCmd{
		cmd:         cmd,
		diffFilesCh: gitdiffFiles,
		errCh:       errCh,
		repoPath:    repoPath,
	}, nil
}

// DiffFilesCh returns a channel with *gitdiff.File.
func (c *GitCmd) DiffFilesCh() <-chan *gitdiff.File {
	return c.diffFilesCh
}

// ErrCh returns a channel that could produce an error if there is something in stderr.
func (c *GitCmd) ErrCh() <-chan error {
	return c.errCh
}

// Wait waits for the command to exit and waits for any copying to
// stdin or copying from stdout or stderr to complete.
//
// Wait also closes underlying stdout and stderr.
func (c *GitCmd) Wait() error {
	return c.cmd.Wait()
}

// cancel stops the Git process so its output channels can be drained without
// waiting for the rest of the command after a fragment worker fails.
func (c *GitCmd) cancel() error {
	if c == nil || c.cmd == nil {
		return nil
	}
	if c.cmd.Cancel != nil {
		if err := c.cmd.Cancel(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		return nil
	}
	if c.cmd.Process == nil {
		return nil
	}
	if err := c.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}

// String displays the command used for GitCmd
func (c *GitCmd) String() string {
	return c.cmd.String()
}

// NewBlobReader returns an io.ReadCloser that can be used to read a blob
// within the git repo used to create the GitCmd.
//
// The caller is responsible for closing the reader.
//
// Deprecated: use NewBlobReaderContext instead.
func (c *GitCmd) NewBlobReader(commit, path string) (io.ReadCloser, error) {
	return c.NewBlobReaderContext(context.Background(), commit, path)
}

// NewBlobReaderContext is the same as NewBlobReader but supports passing in a
// context to use for timeouts
func (c *GitCmd) NewBlobReaderContext(ctx context.Context, commit, path string) (io.ReadCloser, error) {
	gitArgs := []string{"-C", c.repoPath, "cat-file", "blob", commit + ":" + path}
	cmd := exec.CommandContext(ctx, "git", gitArgs...)
	cmd.Env = gitConfigIsolationEnv()
	cmd.Stderr = io.Discard
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start git command: %w", err)
	}
	return &blobReader{
		ReadCloser: stdout,
		cmd:        cmd,
	}, nil
}

// listenForStdErr listens for stderr output from git, prints it to stdout,
// sends to errCh and closes it.
func listenForStdErr(stderr io.ReadCloser, errCh chan<- error, logger *slog.Logger) {
	defer close(errCh)

	var errLines []string

	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		// if git throws one of the following errors:
		//
		//  exhaustive rename detection was skipped due to too many files.
		//  you may want to set your diff.renameLimit variable to at least
		//  (some large number) and retry the command.
		//
		//	inexact rename detection was skipped due to too many files.
		//  you may want to set your diff.renameLimit variable to at least
		//  (some large number) and retry the command.
		//
		//  Auto packing the repository in background for optimum performance.
		//  See "git help gc" for manual housekeeping.
		//
		// we skip exiting the program as git log -p/git diff will continue
		// to send data to stdout and finish executing. This next bit of
		// code prevents Betterleaks from stopping mid scan if this error is
		// encountered
		if strings.Contains(scanner.Text(),
			"exhaustive rename detection was skipped") ||
			strings.Contains(scanner.Text(),
				"inexact rename detection was skipped") ||
			strings.Contains(scanner.Text(),
				"you may want to set your diff.renameLimit") ||
			strings.Contains(scanner.Text(),
				"See \"git help gc\" for manual housekeeping") ||
			strings.Contains(scanner.Text(),
				"Auto packing the repository in background for optimum performance") {
			loggerOrDiscard(logger).Warn(scanner.Text())
		} else {
			line := scanner.Text()
			loggerOrDiscard(logger).Error("git command error", "message", line)
			errLines = append(errLines, line)
		}
	}

	if len(errLines) > 0 {
		errCh <- fmt.Errorf("git stderr: %s", strings.Join(errLines, "; "))
	}
}

// newGitLogCommitsCmd constructs a git log command for an exact set of
// commits. --no-walk keeps worker partitions deterministic and non-overlapping.
func newGitLogCommitsCmd(ctx context.Context, source string, commits []string, logger *slog.Logger) (*GitCmd, error) {
	sourceClean := filepath.Clean(source)
	args := []string{"-C", sourceClean, "log", "-p", "-U0", "--no-walk", "--stdin", "--diff-filter=tuxdb"}

	cmd := exec.CommandContext(ctx, "git", args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	gitCmd, err := startGitCmd(cmd, sourceClean, gitCmdOptions{logger: loggerOrDiscard(logger), stream: true})
	if err != nil {
		return nil, err
	}

	go func() {
		defer stdin.Close()
		writer := bufio.NewWriter(stdin)
		for _, sha := range commits {
			if _, err := fmt.Fprintln(writer, sha); err != nil {
				return
			}
		}
		_ = writer.Flush()
	}()

	return gitCmd, nil
}

// listCommits returns the commits selected by logOpts in deterministic order.
func listCommits(ctx context.Context, source string, logOpts string) ([]string, error) {
	sourceClean := filepath.Clean(source)
	args := []string{"-C", sourceClean, "rev-list"}

	if logOpts != "" {
		userArgs, err := splitGitLogOpts(logOpts)
		if err != nil {
			return nil, fmt.Errorf("invalid --log-opts: %w", err)
		}
		args = append(args, userArgs...)
	} else {
		args = append(args, "--all")
	}

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = gitConfigIsolationEnv()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git rev-list: %w", err)
	}

	text := strings.TrimSpace(string(out))
	if text == "" {
		return nil, nil
	}
	return strings.Split(text, "\n"), nil
}

// ResolveRemote resolves the SCM platform and remote URL for the given source.
// It replaces the deprecated NewRemoteInfo/NewRemoteInfoContext functions.
func ResolveRemote(ctx context.Context, platform scm.Platform, source string) (scm.Platform, string) {
	if platform == scm.NoPlatform {
		return platform, ""
	}

	remoteUrl, err := getRemoteUrl(ctx, source)
	if err != nil {
		if strings.Contains(err.Error(), "No remote configured") {
			platform = scm.NoPlatform
		}
		return platform, ""
	}

	if platform == scm.UnknownPlatform {
		platform = platformFromHost(remoteUrl)
	}

	return platform, remoteUrl.String()
}

var sshUrlpat = regexp.MustCompile(`^git@([a-zA-Z0-9.-]+):(?:\d{1,5}/)?([\w/.-]+?)(?:\.git)?$`)

func getRemoteUrl(ctx context.Context, source string) (*url.URL, error) {
	// This will return the first remote — typically, "origin".
	cmd := exec.CommandContext(ctx, "git", "ls-remote", "--quiet", "--get-url")
	cmd.Env = gitConfigIsolationEnv()
	if source != "." {
		cmd.Dir = source
	}

	stdout, err := cmd.Output()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return nil, fmt.Errorf("command failed (%d): %w, stderr: %s", exitError.ExitCode(), err, string(bytes.TrimSpace(exitError.Stderr)))
		}
		return nil, err
	}

	remoteUrl := string(bytes.TrimSpace(stdout))
	if matches := sshUrlpat.FindStringSubmatch(remoteUrl); matches != nil {
		remoteUrl = fmt.Sprintf("https://%s/%s", matches[1], matches[2])
	}
	remoteUrl = strings.TrimSuffix(remoteUrl, ".git")

	parsedUrl, err := url.Parse(remoteUrl)
	if err != nil {
		return nil, fmt.Errorf("unable to parse remote URL: %w", err)
	}

	// Remove any user info.
	parsedUrl.User = nil
	return parsedUrl, nil
}

func platformFromHost(u *url.URL) scm.Platform {
	switch strings.ToLower(u.Hostname()) {
	case "github.com":
		return scm.GitHubPlatform
	case "gitlab.com":
		return scm.GitLabPlatform
	case "dev.azure.com", "visualstudio.com":
		return scm.AzureDevOpsPlatform
	case "gitea.com", "code.forgejo.org", "codeberg.org":
		return scm.GiteaPlatform
	case "bitbucket.org":
		return scm.BitbucketPlatform
	default:
		return scm.UnknownPlatform
	}
}
