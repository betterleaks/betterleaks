package sources

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gitleaks/go-gitdiff/gitdiff"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources/scm"
)

// GitCmd helps to work with Git's output.
type GitCmd struct {
	cmd         *exec.Cmd
	diffFilesCh <-chan *gitdiff.File
	parseReady  <-chan gitParseResult
	errCh       <-chan error
	repoPath    string
	cancel      context.CancelFunc
	parseOnce   sync.Once
	waitOnce    sync.Once
	waitErr     error
}

type gitParseResult struct {
	files <-chan *gitdiff.File
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
	cmd       *exec.Cmd
	closeOnce sync.Once
	closeErr  error
}

// Close closes the underlying reader and then waits for the command to complete,
// releasing its resources.
func (br *blobReader) Close() error {
	if br == nil {
		return nil
	}
	br.closeOnce.Do(func() {
		// Draining lets cat-file exit normally when archive identification did not
		// consume the entire blob. Wait always reaps the process.
		_, drainErr := io.Copy(io.Discard, br)
		closeErr := br.ReadCloser.Close()
		waitErr := br.cmd.Wait()
		br.closeErr = errors.Join(drainErr, closeErr, waitErr)
	})
	return br.closeErr
}

// NewGitLogCmd starts a git log command tied to ctx.
func NewGitLogCmd(ctx context.Context, source string, logOpts string) (*GitCmd, error) {
	sourceClean := filepath.Clean(source)
	args := []string{"-C", sourceClean, "log", "-p", "-U0"}
	if logOpts != "" {
		userArgs, err := splitGitLogOpts(logOpts)
		if err != nil {
			return nil, fmt.Errorf("invalid --log-opts: %w", err)
		}
		args = append(args, userArgs...)
	} else {
		args = append(args, "--full-history", "--all", "--diff-filter=tuxdb")
	}
	return startGitCmd(ctx, sourceClean, args)
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

// NewGitDiffCmd starts a git diff command tied to ctx.
func NewGitDiffCmd(ctx context.Context, source string, staged bool) (*GitCmd, error) {
	sourceClean := filepath.Clean(source)
	args := []string{"-C", sourceClean, "diff", "-U0", "--no-ext-diff"}
	if staged {
		args = append(args, "--staged")
	}
	args = append(args, ".")
	return startGitCmd(ctx, sourceClean, args)
}

// startGitCmd starts git and transfers ownership of the process and parser
// goroutines to the returned GitCmd.
func startGitCmd(ctx context.Context, repoPath string, args []string) (*GitCmd, error) {
	gitCmd, _, err := startGitCmdInternal(ctx, repoPath, args, false)
	return gitCmd, err
}

func startGitCmdWithStdin(ctx context.Context, repoPath string, args []string) (*GitCmd, io.WriteCloser, error) {
	return startGitCmdInternal(ctx, repoPath, args, true)
}

func startGitCmdInternal(
	ctx context.Context,
	repoPath string,
	args []string,
	withStdin bool,
) (*GitCmd, io.WriteCloser, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cmdCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(cmdCtx, "git", args...)
	cmd.Env = gitConfigIsolationEnv()
	logging.Debug().Msgf("executing: %s", cmd.String())

	var stdin io.WriteCloser
	if withStdin {
		var err error
		stdin, err = cmd.StdinPipe()
		if err != nil {
			cancel()
			return nil, nil, err
		}
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, nil, err
	}

	parseReady, errCh := prepareGitOutput(stdout, stderr)

	return &GitCmd{
		cmd:        cmd,
		parseReady: parseReady,
		errCh:      errCh,
		repoPath:   repoPath,
		cancel:     cancel,
	}, stdin, nil
}

// prepareGitOutput initializes gitdiff parsing asynchronously so stdin-fed Git
// workers can be started before their commit stream is written. Once initialized,
// consumers receive gitdiff's channel directly: bridging every file through a
// second channel would retain one additional parsed patch per Git worker.
func prepareGitOutput(stdout, stderr io.ReadCloser) (<-chan gitParseResult, <-chan error) {
	ready := make(chan gitParseResult, 1)
	errs := make(chan error, 2)
	var readers sync.WaitGroup
	readers.Add(2)

	go func() {
		defer readers.Done()
		parsed, err := gitdiff.Parse(stdout)
		if err != nil {
			errs <- fmt.Errorf("parse git output: %w", err)
			empty := make(chan *gitdiff.File)
			close(empty)
			parsed = empty
		}
		ready <- gitParseResult{files: parsed}
		close(ready)
	}()
	go func() {
		defer readers.Done()
		listenForStdErr(stderr, errs)
	}()
	go func() {
		readers.Wait()
		close(errs)
	}()

	return ready, errs
}

// DiffFilesCh returns a channel with *gitdiff.File.
func (c *GitCmd) DiffFilesCh() <-chan *gitdiff.File {
	if c == nil {
		return nil
	}
	c.parseOnce.Do(func() {
		if c.diffFilesCh != nil || c.parseReady == nil {
			return
		}
		if result, ok := <-c.parseReady; ok {
			c.diffFilesCh = result.files
		}
	})
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
	if c == nil || c.cmd == nil {
		return errors.New("sources: nil git command")
	}
	c.waitOnce.Do(func() {
		c.waitErr = c.cmd.Wait()
		if c.cancel != nil {
			c.cancel()
		}
	})
	return c.waitErr
}

func (c *GitCmd) cancelAndDrain() {
	if c == nil {
		return
	}
	if c.cancel != nil {
		c.cancel()
	}
	for range c.DiffFilesCh() {
	}
	for range c.errCh {
	}
}

// String displays the command used for GitCmd
func (c *GitCmd) String() string {
	if c == nil || c.cmd == nil {
		return ""
	}
	return c.cmd.String()
}

// NewBlobReader returns a reader for a blob in the command's repository.
// The caller must close the reader.
func (c *GitCmd) NewBlobReader(ctx context.Context, commit, path string) (io.ReadCloser, error) {
	if c == nil || c.cmd == nil {
		return nil, errors.New("sources: git command is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
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

// listenForStdErr drains stderr, logs known non-fatal warnings, and reports all
// other output as one error after the stream closes.
func listenForStdErr(stderr io.ReadCloser, errCh chan<- error) {
	defer stderr.Close()

	const maxRetainedStderr = 64 * 1024
	var retained strings.Builder
	truncated := false
	retain := func(line string) {
		if retained.Len() >= maxRetainedStderr {
			truncated = true
			return
		}
		if retained.Len() > 0 {
			retained.WriteString("; ")
		}
		remaining := maxRetainedStderr - retained.Len()
		if len(line) > remaining {
			line = line[:remaining]
			truncated = true
		}
		retained.WriteString(line)
	}

	scanner := bufio.NewScanner(stderr)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
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
		// code prevents gitleaks from stopping mid scan if this error is
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
			logging.Warn().Msg(scanner.Text())
		} else {
			line := scanner.Text()
			logging.Error().Msgf("[git] %s", line)
			retain(line)
		}
	}
	if err := scanner.Err(); err != nil {
		retain(fmt.Sprintf("read stderr: %v", err))
	}

	if retained.Len() > 0 {
		if truncated {
			retained.WriteString(" [truncated]")
		}
		errCh <- fmt.Errorf("git stderr: %s", retained.String())
	}
}

// Git is a source for yielding fragments from a git repo
type Git struct {
	Cmd             *GitCmd
	ShouldSkip      SkipFunc
	Platform        scm.Platform
	RemoteURL       string
	MaxArchiveDepth int
}

// Fragments yields fragments from a git repo.
func (s *Git) Fragments(ctx context.Context, yield FragmentsFunc) error {
	return s.fragments(ctx, yield)
}

func (s *Git) fragments(ctx context.Context, yield FragmentsFunc) (returnErr error) {
	if s == nil || s.Cmd == nil || s.Cmd.cmd == nil {
		return errors.New("sources: git command is required")
	}
	if yield == nil {
		return errors.New("sources: git fragment callback is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	completed := false
	defer func() {
		if !completed {
			// A parser producer may be blocked sending to diffFilesCh when the
			// consumer exits early. Kill git and drain both channels before Wait
			// so neither the process nor parser goroutines can leak.
			s.Cmd.cancelAndDrain()
		}
		waitErr := s.Cmd.Wait()
		if completed && waitErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("%s: %w", s.Cmd.String(), waitErr))
		}
	}()

	var (
		diffFilesCh = s.Cmd.DiffFilesCh()
		errCh       = s.Cmd.ErrCh()
		stderrErr   error
	)

	// loop to range over both DiffFiles (stdout) and ErrCh (stderr)
	for diffFilesCh != nil || errCh != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case gitdiffFile, open := <-diffFilesCh:
			if !open {
				diffFilesCh = nil
				break
			}
			if gitdiffFile == nil {
				continue
			}

			if gitdiffFile.IsDelete {
				continue
			}

			// skip non-archive binary files
			yieldAsArchive := false
			if gitdiffFile.IsBinary {
				if !isArchive(ctx, gitdiffFile.NewName) {
					continue
				}
				yieldAsArchive = true
			}

			// Build commit attributes and check prefilter / allowlists before
			// allocating goroutines or fragment memory.
			commitSHA := ""
			commitAttrs := make(map[string]string)
			if gitdiffFile.PatchHeader != nil {
				commitSHA = gitdiffFile.PatchHeader.SHA
				commitAttrs[AttrGitSHA] = commitSHA
				commitAttrs[AttrGitMessage] = gitdiffFile.PatchHeader.Message()
				commitAttrs[AttrResource] = ResourceGitPatchContent
				commitAttrs[AttrPath] = gitdiffFile.NewName
				if s.RemoteURL != "" {
					commitAttrs[AttrGitRemoteURL] = s.RemoteURL
					commitAttrs[AttrGitPlatform] = s.Platform.String()
				}
				if !gitdiffFile.PatchHeader.AuthorDate.IsZero() {
					commitAttrs[AttrGitDate] = gitdiffFile.PatchHeader.AuthorDate.UTC().Format(time.RFC3339)
				}
				if gitdiffFile.PatchHeader.Author != nil {
					commitAttrs[AttrGitAuthorName] = gitdiffFile.PatchHeader.Author.Name
					commitAttrs[AttrGitAuthorEmail] = gitdiffFile.PatchHeader.Author.Email
				}

				if shouldSkipAttrs(s.ShouldSkip, commitAttrs) {
					logging.Trace().
						Str("commit", commitSHA).
						Str("path", gitdiffFile.NewName).
						Msg("skipping diff entry: global prefilter")
					continue
				}
			}

			if yieldAsArchive {
				blob, err := s.Cmd.NewBlobReader(ctx, commitSHA, gitdiffFile.NewName)
				if err != nil {
					logging.Error().Err(err).Msg("could not read archive blob")
					continue
				}

				file := File{
					Content:         blob,
					Path:            gitdiffFile.NewName,
					MaxArchiveDepth: s.MaxArchiveDepth,
					ShouldSkip:      s.ShouldSkip,
				}

				err = file.Fragments(ctx, func(fragment *Fragment, err error) error {
					// Enrich the leased map in place so Release can return it to
					// the file source's metadata pool.
					for key, value := range commitAttrs {
						if fragment.Attr(key) == "" {
							fragment.SetAttr(key, value)
						}
					}
					return yield(fragment, err)
				})
				closeErr := blob.Close()
				if err != nil || closeErr != nil {
					return errors.Join(err, closeErr)
				}
				continue
			}

			for _, textFragment := range gitdiffFile.TextFragments {
				if textFragment == nil {
					continue
				}
				fragment := Fragment{
					Raw:        addedTextBytes(textFragment),
					StartLine:  int(textFragment.NewPosition),
					Attributes: maps.Clone(commitAttrs),
				}
				fragment.SetAttr(AttrPath, gitdiffFile.NewName)

				if err := yield(&fragment, nil); err != nil {
					return err
				}
			}
		case err, open := <-errCh:
			if !open {
				errCh = nil
				break
			}

			stderrErr = errors.Join(stderrErr, err)
		}
	}

	completed = true
	return errors.Join(stderrErr, ctx.Err())
}

func addedTextBytes(fragment *gitdiff.TextFragment) []byte {
	size := 0
	for _, line := range fragment.Lines {
		if line.Op == gitdiff.OpAdd {
			size += len(line.Line)
		}
	}
	if size == 0 {
		return nil
	}
	raw := make([]byte, 0, size)
	for _, line := range fragment.Lines {
		if line.Op == gitdiff.OpAdd {
			raw = append(raw, line.Line...)
		}
	}
	return raw
}

// ResolveRemote resolves the SCM platform and remote URL for the given source.
func ResolveRemote(ctx context.Context, platform scm.Platform, source string) (scm.Platform, string) {
	if platform == scm.NoPlatform {
		return platform, ""
	}

	remoteUrl, err := getRemoteUrl(ctx, source)
	if err != nil {
		if strings.Contains(err.Error(), "No remote configured") {
			logging.Debug().Msg("skipping finding links: repository has no configured remote.")
			platform = scm.NoPlatform
		} else {
			logging.Error().Err(err).Msg("skipping finding links: unable to parse remote URL")
		}
		return platform, ""
	}

	if platform == scm.UnknownPlatform {
		platform = platformFromHost(remoteUrl)
		if platform == scm.UnknownPlatform {
			logging.Info().
				Str("host", remoteUrl.Hostname()).
				Msg("Unknown SCM platform. Use --platform to include links in findings.")
		} else {
			logging.Debug().
				Str("host", remoteUrl.Hostname()).
				Str("platform", platform.String()).
				Msg("SCM platform parsed from host")
		}
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
