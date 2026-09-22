package sources

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	"github.com/betterleaks/betterleaks/v2/internal/urlredact"
	"github.com/betterleaks/betterleaks/v2/logging"
	sourceworkers "github.com/betterleaks/betterleaks/v2/sources/internal/workers"
	"github.com/betterleaks/betterleaks/v2/sources/scm"
)

// GitMode selects which repository content to scan.
type GitMode string

const (
	// GitHistory scans committed history and is the default mode.
	GitHistory GitMode = ""
	// GitStaged scans additions in the index relative to HEAD.
	GitStaged GitMode = "staged"
	// GitWorkingTree scans tracked working-tree additions relative to the index.
	GitWorkingTree GitMode = "working-tree"
)

// Git yields fragments from a repository. Each Fragments call owns its Git
// processes and waits for them before returning, including on cancellation.
type Git struct {
	// Logger receives source diagnostics. A nil logger disables logging.
	Logger   *slog.Logger
	RepoPath string
	Mode     GitMode
	// URL clones an HTTP(S) repository to a temporary mirror before scanning.
	// It requires GitHistory and is mutually exclusive with RepoPath. Token
	// authenticates the clone; the SDK does not read token environment variables.
	URL   string
	Token string
	// LogOpts selects history with Git log arguments. It requires GitHistory.
	LogOpts string
	// Include adds resources to the default patch scan. Supported values:
	// commit-messages, tag-messages, reflogs. Additional resources require
	// GitHistory mode.
	Include []string

	ShouldSkip      SkipFunc
	Platform        scm.Platform
	RemoteURL       string
	MaxArchiveDepth int
	// Workers bounds concurrent Git history processes. Zero is automatic.
	// Diff modes use one process; scanner detection workers remain independent.
	Workers int
}

const (
	GitResourceTypeCommitMessages = "commit-messages"
	GitResourceTypeTagMessages    = "tag-messages"
	GitResourceTypeReflogs        = "reflogs"
)

// Validate checks Git inputs and additional resource selections before scanning.
func (s *Git) Validate() error {
	switch s.Mode {
	case GitHistory, GitStaged, GitWorkingTree:
	default:
		return fmt.Errorf("unknown Git mode %q", s.Mode)
	}
	if s.Mode != GitHistory && (s.URL != "" || s.LogOpts != "" || len(s.Include) > 0) {
		return errors.New("Git diff modes require a local repository and cannot use LogOpts or Include")
	}
	if s.URL != "" {
		if s.RepoPath != "" {
			return errors.New("Git URL cannot be combined with RepoPath")
		}
		if _, err := parseHTTPSource(s.URL); err != nil {
			return err
		}
	}
	for _, name := range s.Include {
		if name != GitResourceTypeCommitMessages && name != GitResourceTypeTagMessages && name != GitResourceTypeReflogs {
			return fmt.Errorf("unknown Git resource type %q (supported: commit-messages, tag-messages, reflogs)", name)
		}
	}
	return nil
}

// Fragments yields fragments from a git repo
func (s *Git) Fragments(ctx context.Context, yield FragmentsFunc) error {
	budget := sourceworkers.FromContext(ctx)
	if err := s.Validate(); err != nil {
		return err
	}
	if s.URL != "" {
		err := scm.CloneToTempDir(ctx, s.URL, s.Token, "betterleaks-git-*", scm.CloneOptions{Mirror: true}, func(repo string) error {
			local := *s
			local.URL, local.Token, local.RepoPath = "", "", repo
			u, _ := parseHTTPSource(s.URL)
			if local.Platform == scm.UnknownPlatform {
				local.Platform = platformFromHost(u)
			}
			local.RemoteURL = strings.TrimSuffix(urlredact.Public(u), ".git")
			return local.Fragments(ctx, yield)
		})
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if s.RepoPath == "" {
		return errors.New("git source requires URL or RepoPath")
	}
	if s.Mode != GitHistory {
		return budget.Run(ctx, func() error {
			cmd, err := newGitDiffCmd(ctx, s.RepoPath, s.Mode == GitStaged, s.Logger)
			if err != nil {
				return err
			}
			return s.runGitCmd(ctx, yield, cmd)
		})
	}
	if err := s.fragmentsFromRepo(ctx, yield, budget); err != nil {
		return err
	}
	if slices.Contains(s.Include, GitResourceTypeReflogs) {
		if err := budget.Run(ctx, func() error {
			return s.fragmentsFromReflogs(ctx, yield)
		}); err != nil {
			return err
		}
	}
	if slices.Contains(s.Include, GitResourceTypeTagMessages) {
		return budget.Run(ctx, func() error {
			return s.fragmentsFromTagMessages(ctx, yield)
		})
	}
	return nil
}

// fragmentsFromRepo partitions Git history across at most GOMAXPROCS processes.
// Each process consumes fragments serially; the detector provides the other
// half of the bounded worker pipeline.
func (s *Git) fragmentsFromRepo(ctx context.Context, yield FragmentsFunc, budget *sourceworkers.Budget) error {
	workerLimit := sourceworkers.WithinBudget(s.Workers, sourceworkers.AutomaticGit(), budget)
	historyWorkers := min(workerLimit, sourceworkers.Automatic())

	includeMessages := slices.Contains(s.Include, GitResourceTypeCommitMessages)
	includeReflogs := slices.Contains(s.Include, GitResourceTypeReflogs)
	if historyWorkers <= 1 && !includeMessages && !includeReflogs {
		return budget.Run(ctx, func() error {
			return s.runFullHistory(ctx, yield)
		})
	}

	var commits []string
	err := budget.Run(ctx, func() error {
		var err error
		commits, err = listCommits(ctx, s.RepoPath, s.LogOpts, includeReflogs)
		return err
	})
	if err != nil {
		return fmt.Errorf("list commits: %w", err)
	}
	if len(commits) == 0 {
		return nil
	}

	workers := min(historyWorkers, len(commits))
	if workers == 1 && !includeMessages && !includeReflogs {
		return budget.Run(ctx, func() error {
			return s.runFullHistory(ctx, yield)
		})
	}

	chunkSize := (len(commits) + workers - 1) / workers
	logging.OrDiscard(s.Logger).Debug("parallel git scan", "commits", len(commits), "workers", workers, "chunk_size", chunkSize)

	g, groupCtx := errgroup.WithContext(ctx)
	for i := range workers {
		start := i * chunkSize
		if start >= len(commits) {
			break
		}
		end := min(start+chunkSize, len(commits))
		chunk := commits[start:end]
		g.Go(func() error {
			return budget.Run(groupCtx, func() error {
				return s.runHistoryChunk(groupCtx, yield, chunk)
			})
		})
	}
	return g.Wait()
}

func (s *Git) runFullHistory(ctx context.Context, yield FragmentsFunc) error {
	cmd, err := newGitLogCmd(ctx, s.RepoPath, s.LogOpts, s.Logger)
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
// resembles a patch header. The caller already holds a budget slot, so this does
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
		if fragment.Raw == "" || (s.ShouldSkip != nil && s.ShouldSkip(fragment.Attributes)) {
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
	for line := range strings.SplitSeq(headers, "\n") {
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
// caller holds a budget slot; one cat-file process handles all tag objects,
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
		if fragment.Raw == "" || (s.ShouldSkip != nil && s.ShouldSkip(fragment.Attributes)) {
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

// fragmentsFromReflogs scans the entry messages exposed by Git's reflog walk.
// These are separate records from commit messages, with the ref updater's
// identity and timestamp. LogOpts selects commit history, not entry messages.
func (s *Git) fragmentsFromReflogs(ctx context.Context, yield FragmentsFunc) (scanErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", s.RepoPath, "log",
		"--walk-reflogs", "--all", "--no-patch", "--no-color", "--no-decorate",
		"--no-notes", "--no-show-signature", "-z", "--date=raw",
		"--format=%H%x00%gD%x00%gn%x00%ge%x00%gs")
	cmd.Env = gitConfigIsolationEnv()
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
			scanErr = fmt.Errorf("read Git reflogs: %w", waitErr)
		}
		if scanErr != nil && stderr.Len() > 0 {
			scanErr = fmt.Errorf("%w: %s", scanErr, strings.TrimSpace(stderr.String()))
		}
	}()

	reader := bufio.NewReader(stdout)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		fragment, err := readGitReflogMessage(reader)
		if err == io.EOF {
			return ctx.Err()
		}
		if err != nil {
			return fmt.Errorf("read Git reflog entry: %w", err)
		}
		if s.RemoteURL != "" {
			fragment.SetAttr(AttrGitRemoteURL, s.RemoteURL)
			fragment.SetAttr(AttrGitPlatform, s.Platform.String())
		}
		if fragment.Raw == "" || (s.ShouldSkip != nil && s.ShouldSkip(fragment.Attributes)) {
			continue
		}
		if err := yield(fragment, nil); err != nil {
			return err
		}
	}
}

func readGitReflogMessage(reader *bufio.Reader) (Fragment, error) {
	// Git normalizes reflog messages as C strings. NUL framing separates
	// fields without treating tabs, newlines, or long messages as records.
	var fields [5]string
	for i := range fields {
		value, err := reader.ReadString(0)
		if err != nil {
			if err == io.EOF && (i > 0 || len(value) > 0) {
				err = io.ErrUnexpectedEOF
			}
			return Fragment{}, err
		}
		fields[i] = strings.TrimSuffix(value, "\x00")
	}
	selector := fields[1]
	dateStart := strings.LastIndex(selector, "@{")
	if fields[0] == "" || dateStart <= 0 || !strings.HasSuffix(selector, "}") {
		return Fragment{}, fmt.Errorf("invalid reflog selector %q", selector)
	}
	// %gD with --date=raw contains the reflog timestamp. Commit date
	// placeholders would incorrectly report the referenced commit's date.
	date, err := gitdiff.ParsePatchDate(selector[dateStart+2 : len(selector)-1])
	if err != nil {
		return Fragment{}, fmt.Errorf("parse reflog date: %w", err)
	}
	attrs := map[string]string{
		AttrResource:            ResourceGitReflogMessage,
		AttrGitSHA:              fields[0],
		AttrGitReflogSelector:   selector,
		AttrGitReflogRef:        selector[:dateStart],
		AttrGitReflogActorName:  fields[2],
		AttrGitReflogActorEmail: fields[3],
		AttrGitDate:             date.UTC().Format(time.RFC3339),
		AttrGitMessage:          fields[4],
	}
	return Fragment{Raw: fields[4], StartLine: 1, Attributes: attrs}, nil
}

func (s *Git) runGitCmd(ctx context.Context, yield FragmentsFunc, cmd *gitCmd) error {
	readErr := readGitPatch(ctx, cmd.stdout, func(file *gitdiff.File) (gitHunkFunc, error) {
		if file.IsDelete {
			return nil, nil
		}
		attrs := s.gitAttributes(file)
		if s.ShouldSkip != nil && s.ShouldSkip(attrs) {
			logging.OrDiscard(s.Logger).Log(ctx, logging.LevelTrace, "skipping diff entry: global prefilter", "commit", attrs[AttrGitSHA], "path", file.NewName)
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
		cancelErr := cmd.cmd.Process.Kill()
		if errors.Is(cancelErr, os.ErrProcessDone) {
			cancelErr = nil
		}
		stopped = cancelErr == nil
		readErr = errors.Join(readErr, cancelErr)
	}
	for err := range cmd.errCh {
		readErr = errors.Join(readErr, err)
	}
	waitErr := cmd.cmd.Wait()
	var exitErr *exec.ExitError
	if stopped && errors.As(waitErr, &exitErr) && exitErr.ExitCode() == -1 {
		// Killing Git is cleanup after the original failure. Its signal exit
		// adds no diagnostic value; retain parser, callback, and stderr errors.
		waitErr = nil
	}
	return errors.Join(readErr, waitErr)
}

func (s *Git) fragmentsFromArchive(ctx context.Context, path string, commitAttrs map[string]string, yield FragmentsFunc) error {
	blob, err := newGitBlobReader(ctx, s.RepoPath, commitAttrs[AttrGitSHA], path)
	if err != nil {
		logging.OrDiscard(s.Logger).Error("could not read archive blob", "error", err)
		return nil
	}
	file := File{
		Logger:          s.Logger,
		Content:         blob,
		Path:            path,
		Attributes:      commitAttrs,
		MaxArchiveDepth: s.MaxArchiveDepth,
		ShouldSkip:      s.ShouldSkip,
	}
	err = file.Fragments(ctx, yield)
	if closeErr := blob.Close(); closeErr != nil {
		logging.OrDiscard(s.Logger).Debug("blobReader.Close() returned an error", "error", closeErr)
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

type gitCmd struct {
	cmd    *exec.Cmd
	stdout io.Reader
	errCh  <-chan error
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

func newGitLogCmd(ctx context.Context, source, logOpts string, logger *slog.Logger) (*gitCmd, error) {
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
	return startGitCmd(cmd, logger)
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

func newGitDiffCmd(ctx context.Context, source string, staged bool, logger *slog.Logger) (*gitCmd, error) {
	sourceClean := filepath.Clean(source)
	args := []string{"-C", sourceClean, "diff", "-U0", "--no-ext-diff"}
	if staged {
		args = append(args, "--staged")
	}
	args = append(args, ".")
	return startGitCmd(exec.CommandContext(ctx, "git", args...), logger)
}

// startGitCmd starts a patch-producing command. The caller must consume stdout,
// drain errCh, and wait for the process, including after a parse or callback error.
func startGitCmd(cmd *exec.Cmd, logger *slog.Logger) (*gitCmd, error) {
	cmd.Env = gitConfigIsolationEnv()

	logging.OrDiscard(logger).Debug("executing git command", "command", cmd.String())

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
	go listenForStdErr(stderr, errCh, logger)

	return &gitCmd{cmd: cmd, stdout: stdout, errCh: errCh}, nil
}

// newGitBlobReader reads a committed blob, or an index blob when commit is empty.
// The caller must close the reader to release the Git process.
func newGitBlobReader(ctx context.Context, repoPath, commit, path string) (io.ReadCloser, error) {
	gitArgs := []string{"-C", repoPath, "cat-file", "blob", commit + ":" + path}
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
			logging.OrDiscard(logger).Warn(scanner.Text())
		} else {
			line := scanner.Text()
			logging.OrDiscard(logger).Error("git command error", "message", line)
			errLines = append(errLines, line)
		}
	}

	if len(errLines) > 0 {
		errCh <- fmt.Errorf("git stderr: %s", strings.Join(errLines, "; "))
	}
}

// newGitLogCommitsCmd constructs a git log command for an exact set of
// commits. --no-walk keeps worker partitions deterministic and non-overlapping.
func newGitLogCommitsCmd(ctx context.Context, source string, commits []string, logger *slog.Logger) (*gitCmd, error) {
	sourceClean := filepath.Clean(source)
	args := []string{"-C", sourceClean, "log", "-p", "-U0", "--no-walk", "--stdin", "--diff-filter=tuxdb"}

	cmd := exec.CommandContext(ctx, "git", args...)
	// Let os/exec own the input-copy goroutine so Wait joins it on every exit.
	cmd.Stdin = strings.NewReader(strings.Join(commits, "\n") + "\n")
	return startGitCmd(cmd, logger)
}

// listCommits returns the commits selected by logOpts in deterministic order.
// Reflog roots join the same walk as ordinary refs, so Git visits each commit
// once even when multiple refs and reflog entries refer to it.
func listCommits(ctx context.Context, source string, logOpts string, includeReflogs bool) ([]string, error) {
	sourceClean := filepath.Clean(source)
	args := []string{"-C", sourceClean, "rev-list"}
	if includeReflogs {
		args = append(args, "--reflog")
	}

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
