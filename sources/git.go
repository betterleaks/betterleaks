package sources

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/fatih/semgroup"
	"github.com/gitleaks/go-gitdiff/gitdiff"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources/scm"
)

// GitCmd helps to work with Git's output.
type GitCmd struct {
	cmd         *exec.Cmd
	diffFilesCh <-chan *gitdiff.File
	errCh       <-chan error
	repo        *gitRepo
	ownsRepo    bool

	mu      sync.Mutex
	waiting bool           // Wait has started; no new blob readers
	blobs   sync.WaitGroup // open blob readers, which still use repo
}

// GitOptions controls how Betterleaks runs Git against a local repository.
//
// By default Git runs against a private Git directory that shares the
// repository's objects. Only validated format and working-tree settings and
// sparse-checkout patterns are carried over; executable configuration, hooks,
// and .git/info/attributes are not loaded by scanning commands. History scans
// copy only .mailmap from the working tree, so its .gitattributes do not apply.
type GitOptions struct {
	// TrustLocalGitConfig runs Git directly in the repository. Repository
	// configuration and hooks can then execute programs with Betterleaks'
	// privileges, so only set it for repositories whose .git directory you trust.
	TrustLocalGitConfig bool
}

// NewLogCmd starts a history scan of the repository at source. Consume the
// command's output, then call Wait to release its resources.
func (o GitOptions) NewLogCmd(ctx context.Context, source, logOpts string) (*GitCmd, error) {
	repo, err := openGitRepo(ctx, source, o, false)
	if err != nil {
		return nil, err
	}
	cmd, err := newGitLogCmd(ctx, repo, logOpts)
	if err != nil {
		repo.Close()
		return nil, err
	}
	cmd.ownsRepo = true
	return cmd, nil
}

// NewDiffCmd starts a scan of the unstaged changes in the working tree at
// source or, if staged is set, of its staged changes. Consume the command's
// output, then call Wait to release its resources.
func (o GitOptions) NewDiffCmd(ctx context.Context, source string, staged bool) (*GitCmd, error) {
	repo, err := openGitRepo(ctx, source, o, true)
	if err != nil {
		return nil, err
	}
	args := []string{"diff", "-U0", "--no-ext-diff"}
	if staged {
		args = append(args, "--staged")
	}
	if !o.TrustLocalGitConfig {
		// Checking a submodule for changes runs Git with its configuration.
		args = append(args, "--ignore-submodules=all")
	}
	cmd, err := startGitLogCmd(ctx, repo, append(args, "."))
	if err != nil {
		repo.Close()
		return nil, err
	}
	cmd.ownsRepo = true
	return cmd, nil
}

// gitConfigIsolationEnv contains the standard Git configuration isolation environment variables.
// These settings prevent Git from reading user or system configuration files.
func gitConfigIsolationEnv() []string {
	// Git recognizes /dev/null on Windows too; Git for Windows 2.56.0 rejects NUL.
	const nullDevice = "/dev/null"
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
	cmd  *exec.Cmd
	done func()
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
	br.done()
	// Return the first error encountered
	if drainErr != nil {
		return drainErr
	}
	if closeErr != nil {
		return closeErr
	}
	return waitErr
}

// NewGitLogCmd returns `*DiffFilesCmd` with two channels: `<-chan *gitdiff.File` and `<-chan error`.
// Caller should read everything from channels until receiving a signal about their closure and call
// the `func (*DiffFilesCmd) Wait()` error in order to release resources.
//
// Deprecated: use NewGitLogCmdContext instead.
func NewGitLogCmd(source string, logOpts string) (*GitCmd, error) {
	return NewGitLogCmdContext(context.Background(), source, logOpts)
}

// NewGitLogCmdContext is the same as NewGitLogCmd but supports passing in a
// context to use for timeouts. The repository's local Git configuration is not
// trusted; see GitOptions.
func NewGitLogCmdContext(ctx context.Context, source string, logOpts string) (*GitCmd, error) {
	return GitOptions{}.NewLogCmd(ctx, source, logOpts)
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

// NewGitDiffCmd returns `*DiffFilesCmd` with two channels: `<-chan *gitdiff.File` and `<-chan error`.
// Caller should read everything from channels until receiving a signal about their closure and call
// the `func (*DiffFilesCmd) Wait()` error in order to release resources.
//
// Deprecated: use NewGitDiffCmdContext instead.
func NewGitDiffCmd(source string, staged bool) (*GitCmd, error) {
	return NewGitDiffCmdContext(context.Background(), source, staged)
}

// NewGitDiffCmdContext is the same as NewGitDiffCmd but supports passing in a
// context to use for timeouts. The repository's local Git configuration is not
// trusted; see GitOptions.
func NewGitDiffCmdContext(ctx context.Context, source string, staged bool) (*GitCmd, error) {
	return GitOptions{}.NewDiffCmd(ctx, source, staged)
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
// Wait also closes underlying stdout and stderr. Once blob readers created by
// the command are closed, it removes any private Git directory.
func (c *GitCmd) Wait() error {
	err := c.cmd.Wait()
	c.mu.Lock()
	c.waiting = true
	c.mu.Unlock()
	c.blobs.Wait()
	if c.ownsRepo {
		c.repo.Close()
	}
	return err
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
	cmd := c.repo.command(ctx, "cat-file", "blob", commit+":"+path)
	cmd.Stderr = io.Discard
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdout pipe: %w", err)
	}
	c.mu.Lock()
	if c.waiting {
		c.mu.Unlock()
		_ = stdout.Close()
		return nil, errors.New("git command has finished")
	}
	c.blobs.Add(1)
	c.mu.Unlock()
	if err := cmd.Start(); err != nil {
		c.blobs.Done()
		return nil, fmt.Errorf("failed to start git command: %w", err)
	}
	return &blobReader{
		ReadCloser: stdout,
		cmd:        cmd,
		done:       c.blobs.Done,
	}, nil
}

// listenForStdErr listens for stderr output from git, prints it to stdout,
// sends to errCh and closes it.
func listenForStdErr(stderr io.ReadCloser, errCh chan<- error) {
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
			errLines = append(errLines, line)
		}
	}

	if len(errLines) > 0 {
		errCh <- fmt.Errorf("git stderr: %s", strings.Join(errLines, "; "))
	}
}

// Git is a source for yielding fragments from a git repo
type Git struct {
	Cmd             *GitCmd
	ShouldSkip      SkipFunc
	Platform        scm.Platform
	RemoteURL       string
	Sema            *semgroup.Group
	MaxArchiveDepth int
}

// Fragments yields fragments from a git repo
func (s *Git) Fragments(ctx context.Context, yield FragmentsFunc) (err error) {
	var (
		diffFilesCh = s.Cmd.DiffFilesCh()
		errCh       = s.Cmd.ErrCh()
		wg          sync.WaitGroup
		gitFailed   bool // Git's stderr has been reported
	)
	defer func() {
		if diffFilesCh != nil || errCh != nil {
			// Early returns must stop Git and drain the parser before waiting.
			// Otherwise Git or its parser can remain blocked on unread output.
			_ = s.Cmd.cmd.Process.Kill()
			for diffFilesCh != nil || errCh != nil {
				select {
				case _, open := <-diffFilesCh:
					if !open {
						diffFilesCh = nil
					}
				case _, open := <-errCh:
					if !open {
						errCh = nil
					}
				}
			}
		}
		// Callbacks must finish before the detector closes its results channel
		// or Wait removes the repository used by archive readers.
		wg.Wait()
		waitErr := s.Cmd.Wait()
		if waitErr != nil && err == nil && ctx.Err() == nil && !gitFailed {
			// Git stopped without saying why, for example because it was
			// killed. Report it like Git's own errors.
			err = yield(Fragment{}, fmt.Errorf("git failed: %w", waitErr))
		}
		err = errors.Join(err, ctx.Err())
	}()

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

			wg.Add(1)
			var started atomic.Bool
			s.Sema.Go(func() error {
				if !started.CompareAndSwap(false, true) {
					return nil
				}
				defer wg.Done()

				if yieldAsArchive {
					blob, err := s.Cmd.NewBlobReaderContext(ctx, commitSHA, gitdiffFile.NewName)
					if err != nil {
						logging.Error().Err(err).Msg("could not read archive blob")
						return nil
					}

					file := File{
						Content:         blob,
						Path:            gitdiffFile.NewName,
						MaxArchiveDepth: s.MaxArchiveDepth,
						ShouldSkip:      s.ShouldSkip,
					}

					// enrich and yield fragments
					err = file.Fragments(ctx, func(fragment Fragment, err error) error {
						// create base attributes of the commit
						attrs := maps.Clone(commitAttrs)
						// add fragment-specific attributes (in case attributes have been enriched by the file source)
						maps.Copy(attrs, fragment.Attributes)
						// set the merged attributes back to the fragment that will be yielded
						fragment.Attributes = attrs
						return yield(fragment, err)
					})

					// Close the blob reader and log any issues
					if err := blob.Close(); err != nil {
						logging.Debug().Err(err).Msg("blobReader.Close() returned an error")
					}

					return err
				}

				for _, textFragment := range gitdiffFile.TextFragments {
					if textFragment == nil {
						return nil
					}
					fragment := Fragment{
						Raw:        textFragment.Raw(gitdiff.OpAdd),
						StartLine:  int(textFragment.NewPosition),
						Attributes: commitAttrs,
					}
					fragment.SetAttr(AttrPath, gitdiffFile.NewName)

					if err := yield(fragment, nil); err != nil {
						return err
					}
				}

				return nil
			})
			// semgroup.Go does not start the callback when acquiring a slot
			// is canceled. Retire that task, or let an already running task
			// finish and release its own slot in the local wait group.
			if ctx.Err() != nil && started.CompareAndSwap(false, true) {
				wg.Done()
			}
		case gitErr, open := <-errCh:
			if !open {
				errCh = nil
				break
			}

			// Report the error, then keep scanning what Git wrote before it
			// failed. Returning it would also cancel other ParallelGit workers.
			gitFailed = true
			if err := yield(Fragment{}, gitErr); err != nil {
				return err
			}
		}
	}

	return nil
}

// ResolveRemote resolves the SCM platform and remote URL for the given source.
// It replaces the deprecated NewRemoteInfo/NewRemoteInfoContext functions.
func ResolveRemote(ctx context.Context, platform scm.Platform, source string) (scm.Platform, string) {
	if platform == scm.NoPlatform {
		return platform, ""
	}

	remoteUrl, err := getRemoteUrl(ctx, source)
	if err != nil {
		if errors.Is(err, errNoGitRemote) {
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
	remoteUrl, err := gitRemoteURL(ctx, source)
	if err != nil {
		return nil, err
	}
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
