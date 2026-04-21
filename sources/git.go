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

	"github.com/fatih/semgroup"
	"github.com/gitleaks/go-gitdiff/gitdiff"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources/scm"
)

var quotedOptPattern = regexp.MustCompile(`^(?:"[^"]+"|'[^']+')$`)

// GitCmd helps to work with Git's output.
type GitCmd struct {
	cmd         *exec.Cmd
	diffFilesCh <-chan *gitdiff.File
	errCh       <-chan error
	repoPath    string
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

// NewGitLogCmd returns `*DiffFilesCmd` with two channels: `<-chan *gitdiff.File` and `<-chan error`.
// Caller should read everything from channels until receiving a signal about their closure and call
// the `func (*DiffFilesCmd) Wait()` error in order to release resources.
//
// Deprecated: use NewGitLogCmdContext instead.
func NewGitLogCmd(source string, logOpts string) (*GitCmd, error) {
	return NewGitLogCmdContext(context.Background(), source, logOpts)
}

// NewGitLogCmdContext is the same as NewGitLogCmd but supports passing in a
// context to use for timeouts
func NewGitLogCmdContext(ctx context.Context, source string, logOpts string) (*GitCmd, error) {
	sourceClean := filepath.Clean(source)
	var cmd *exec.Cmd
	if logOpts != "" {
		args := []string{"-C", sourceClean, "log", "-p", "-U0"}

		// Ensure that the user-provided |logOpts| aren't wrapped in quotes.
		// https://github.com/gitleaks/gitleaks/issues/1153
		userArgs := strings.Split(logOpts, " ")
		var quotedOpts []string
		for _, element := range userArgs {
			if quotedOptPattern.MatchString(element) {
				quotedOpts = append(quotedOpts, element)
			}
		}
		if len(quotedOpts) > 0 {
			logging.Warn().Msgf("the following `--log-opts` values may not work as expected: %v\n\tsee https://github.com/gitleaks/gitleaks/issues/1153 for more information", quotedOpts)
		}

		args = append(args, userArgs...)
		cmd = exec.CommandContext(ctx, "git", args...)
	} else {
		cmd = exec.CommandContext(ctx, "git", "-C", sourceClean, "log", "-p", "-U0",
			"--full-history", "--all", "--diff-filter=tuxdb")
	}
	cmd.Env = gitConfigIsolationEnv()

	logging.Debug().Msgf("executing: %s", cmd.String())

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
	go listenForStdErr(stderr, errCh)

	gitdiffFiles, err := gitdiff.Parse(stdout)
	if err != nil {
		return nil, err
	}

	return &GitCmd{
		cmd:         cmd,
		diffFilesCh: gitdiffFiles,
		errCh:       errCh,
		repoPath:    sourceClean,
	}, nil
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
// context to use for timeouts
func NewGitDiffCmdContext(ctx context.Context, source string, staged bool) (*GitCmd, error) {
	sourceClean := filepath.Clean(source)
	var cmd *exec.Cmd
	cmd = exec.CommandContext(ctx, "git", "-C", sourceClean, "diff", "-U0", "--no-ext-diff", ".")
	if staged {
		cmd = exec.CommandContext(ctx, "git", "-C", sourceClean, "diff", "-U0", "--no-ext-diff",
			"--staged", ".")
	}
	cmd.Env = gitConfigIsolationEnv()
	logging.Debug().Msgf("executing: %s", cmd.String())

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
	go listenForStdErr(stderr, errCh)

	gitdiffFiles, err := gitdiff.Parse(stdout)
	if err != nil {
		return nil, err
	}

	return &GitCmd{
		cmd:         cmd,
		diffFilesCh: gitdiffFiles,
		errCh:       errCh,
		repoPath:    sourceClean,
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
func listenForStdErr(stderr io.ReadCloser, errCh chan<- error) {
	defer close(errCh)

	var errEncountered bool

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
			logging.Error().Msgf("[git] %s", scanner.Text())
			errEncountered = true
		}
	}

	if errEncountered {
		errCh <- errors.New("stderr is not empty")
		return
	}
}

// Git is a source for yielding fragments from a git repo
type Git struct {
	Cmd             *GitCmd
	Skip            SkipFunc
	Platform        scm.Platform
	RemoteURL       string
	Sema            *semgroup.Group
	MaxArchiveDepth int
}

// Fragments yields fragments from a git repo
func (s *Git) Fragments(ctx context.Context, yield FragmentsFunc) error {
	defer func() {
		if err := s.Cmd.Wait(); err != nil {
			logging.Debug().Err(err).Str("cmd", s.Cmd.String()).Msg("command aborted")
		}
	}()

	var (
		diffFilesCh = s.Cmd.DiffFilesCh()
		errCh       = s.Cmd.ErrCh()
		wg          sync.WaitGroup
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
				commitAttrs[AttrResourceKind] = "git.diff"
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

				if shouldSkipAttrs(s.Skip, commitAttrs) {
					logging.Trace().
						Str("commit", commitSHA).
						Str("path", gitdiffFile.NewName).
						Msg("skipping diff entry: global prefilter")
					continue
				}
			}

			wg.Add(1)
			s.Sema.Go(func() error {
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
						Skip:            s.Skip,
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
		case err, open := <-errCh:
			if !open {
				errCh = nil
				break
			}

			return yield(Fragment{}, err)
		}
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		wg.Wait()
		return nil
	}
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
