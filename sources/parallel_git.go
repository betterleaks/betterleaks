package sources

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/fatih/semgroup"
	"github.com/gitleaks/go-gitdiff/gitdiff"
	"golang.org/x/sync/errgroup"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/logging"
)

// ParallelGit scans a git repo by running multiple `git log -p` processes
// in parallel, each covering a distinct set of commits. Commit SHAs are
// enumerated once via `git rev-list` and then partitioned across workers,
// guaranteeing deterministic, non-overlapping coverage regardless of
// timestamp ties in the commit graph.
type ParallelGit struct {
	RepoPath        string
	Config          *config.Config
	Remote          *RemoteInfo
	Sema            *semgroup.Group
	MaxArchiveDepth int
	LogOpts         string
	Workers         int // 0 means auto (min(NumCPU, 4))
}

func (s *ParallelGit) workers() int {
	if s.Workers > 0 {
		return s.Workers
	}
	return min(runtime.NumCPU(), 4)
}

// Fragments implements Source by partitioning commits across
// multiple parallel git log workers.
func (s *ParallelGit) Fragments(ctx context.Context, yield FragmentsFunc) error {
	commits, err := listCommits(ctx, s.RepoPath, s.LogOpts)
	if err != nil {
		return fmt.Errorf("list commits: %w", err)
	}

	count := len(commits)
	workers := s.workers()
	if count == 0 {
		return nil
	}
	if workers > count {
		workers = count
	}

	// For very small repos, just run a single worker (no overhead)
	if workers <= 1 {
		return s.runSingleWorker(ctx, yield)
	}

	chunkSize := (count + workers - 1) / workers
	logging.Info().Int("commits", count).Int("workers", workers).Int("chunk_size", chunkSize).Msg("parallel git scan")

	g, gctx := errgroup.WithContext(ctx)
	for i := range workers {
		start := i * chunkSize
		end := min(start+chunkSize, count)
		chunk := commits[start:end]
		g.Go(func() error {
			return s.runWorkerCommits(gctx, yield, chunk)
		})
	}

	return g.Wait()
}

// runSingleWorker runs a full git log (no partitioning) for small repos or
// single-worker mode.
func (s *ParallelGit) runSingleWorker(ctx context.Context, yield FragmentsFunc) error {
	gitCmd, err := newGitLogCmd(ctx, s.RepoPath, s.LogOpts)
	if err != nil {
		return err
	}

	src := &Git{
		Cmd:             gitCmd,
		Config:          s.Config,
		Remote:          s.Remote,
		Sema:            s.Sema,
		MaxArchiveDepth: s.MaxArchiveDepth,
	}

	return src.Fragments(ctx, yield)
}

// runWorkerCommits runs a git log process for a specific set of commit SHAs,
// piped via stdin with --no-walk.
func (s *ParallelGit) runWorkerCommits(ctx context.Context, yield FragmentsFunc, commits []string) error {
	gitCmd, err := newGitLogCommitsCmd(ctx, s.RepoPath, commits)
	if err != nil {
		return err
	}

	src := &Git{
		Cmd:             gitCmd,
		Config:          s.Config,
		Remote:          s.Remote,
		Sema:            s.Sema,
		MaxArchiveDepth: s.MaxArchiveDepth,
	}

	return src.Fragments(ctx, yield)
}

// newGitLogCmd constructs a full git log -p command (no partitioning).
func newGitLogCmd(ctx context.Context, source string, logOpts string) (*GitCmd, error) {
	sourceClean := filepath.Clean(source)
	args := []string{"-C", sourceClean, "log", "-p", "-U0"}

	if logOpts != "" {
		userArgs := strings.Split(logOpts, " ")
		var quotedOpts []string
		for _, element := range userArgs {
			if quotedOptPattern.MatchString(element) {
				quotedOpts = append(quotedOpts, element)
			}
		}
		if len(quotedOpts) > 0 {
			logging.Warn().Msgf("the following `--log-opts` values may not work as expected: %v", quotedOpts)
		}
		args = append(args, userArgs...)
	} else {
		args = append(args, "--full-history", "--all", "--diff-filter=tuxdb")
	}

	return startGitLogCmd(ctx, sourceClean, args)
}

// newGitLogCommitsCmd constructs a git log -p command that processes a specific
// set of commits via --no-walk --stdin. This avoids non-deterministic ordering
// issues with --skip/--max-count on repos with timestamp ties.
func newGitLogCommitsCmd(ctx context.Context, source string, commits []string) (*GitCmd, error) {
	sourceClean := filepath.Clean(source)
	args := []string{"-C", sourceClean, "log", "-p", "-U0", "--no-walk", "--stdin", "--diff-filter=tuxdb"}

	cmd := exec.CommandContext(ctx, "git", args...)
	logging.Debug().Msgf("executing: %s (%d commits via stdin)", cmd.String(), len(commits))

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
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

	go func() {
		defer stdin.Close()
		for _, sha := range commits {
			if _, err := fmt.Fprintln(stdin, sha); err != nil {
				return
			}
		}
	}()

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

// startGitLogCmd is the shared tail for starting a git log process, wiring up
// stdout/stderr pipes, and returning a GitCmd.
func startGitLogCmd(ctx context.Context, repoPath string, args []string) (*GitCmd, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
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
		repoPath:    repoPath,
	}, nil
}

// listCommits returns all commit SHAs matching the given log options.
// The order is deterministic for a given repo state (reverse chronological
// from a single rev-list invocation), which is critical for correct
// partitioning across workers.
func listCommits(ctx context.Context, source string, logOpts string) ([]string, error) {
	sourceClean := filepath.Clean(source)
	args := []string{"-C", sourceClean, "rev-list"}

	if logOpts != "" {
		args = append(args, strings.Split(logOpts, " ")...)
	} else {
		args = append(args, "--all")
	}

	cmd := exec.CommandContext(ctx, "git", args...)
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

// commitCount returns the number of commits matching the given log options.
func commitCount(ctx context.Context, source string, logOpts string) (int, error) {
	sourceClean := filepath.Clean(source)
	args := []string{"-C", sourceClean, "rev-list", "--count"}

	if logOpts != "" {
		args = append(args, strings.Split(logOpts, " ")...)
	} else {
		args = append(args, "--all")
	}

	cmd := exec.CommandContext(ctx, "git", args...)
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("git rev-list --count: %w", err)
	}

	return strconv.Atoi(strings.TrimSpace(string(out)))
}
