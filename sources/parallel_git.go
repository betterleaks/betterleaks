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

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources/scm"
)

// ParallelGit scans a git repo with a fixed pool of git log -p worker
// processes. Commit SHAs are enumerated once via git rev-list, split into many
// small batches, and drained from a shared queue by the workers. Every commit
// belongs to exactly one batch and every batch runs on exactly one worker, so
// coverage is complete and non-overlapping. Findings are independent of scan
// order, so it does not matter which worker runs a given batch.
type ParallelGit struct {
	RepoPath        string
	ShouldSkip      SkipFunc
	Platform        scm.Platform
	RemoteURL       string
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

// Fragments implements Source. It scans the repo's commits with a fixed pool
// of concurrent git log workers; the first worker to error cancels the others
// and that error is returned. It falls back to a single git log process when
// commit enumeration fails or when only one worker would run, matching a
// non-parallel scan.
func (s *ParallelGit) Fragments(ctx context.Context, yield FragmentsFunc) error {
	commits, err := listCommits(ctx, s.RepoPath, s.LogOpts)
	if err != nil {
		// Some --log-opts are valid for `git log` but not `git rev-list`
		// (e.g. `-n 5` with no ref). Fall back to a single `git log -p`
		// process, which preserves the exact non-partitioned behavior.
		// A genuinely broken repo or bad revision still surfaces an error
		// through the fallback's own git log; Warn makes the loss of
		// parallelism visible at default verbosity.
		logging.Warn().Err(err).Msg("git rev-list failed; falling back to a single git log process (no parallelism)")
		return s.runSingleWorker(ctx, yield)
	}

	count := len(commits)
	workers := s.workers()
	if count == 0 {
		return nil
	}
	if workers > count {
		workers = count
	}

	// One effective worker (single CPU, Workers=1, or a one-commit repo) has
	// nothing to parallelize; skip the batching machinery.
	if workers <= 1 {
		return s.runSingleWorker(ctx, yield)
	}

	// Commit diff sizes are heavy-tailed, and heavy commits cluster in
	// contiguous stretches of history (e.g. vendored-dependency churn), so a
	// contiguous partition landing on a cluster straggles while other workers
	// idle. Two mitigations compose: batches stride across all of history
	// (batch b holds commits b, b+numBatches, b+2*numBatches, ...) so each
	// samples heavy regions evenly, and workers pull from a shared queue so
	// residual imbalance self-corrects. Aim for about 8 batches per worker:
	// enough to smooth the tail through stealing, few enough to amortize git
	// process startup, with a 64-commit floor so small repos do not spawn a
	// process per handful of commits.
	batchSize := max(count/(workers*8), 64)
	numBatches := (count + batchSize - 1) / batchSize
	logging.Info().Int("commits", count).Int("workers", workers).Int("batch_size", batchSize).Int("batches", numBatches).Msg("parallel git scan")

	batches := make(chan []string, numBatches)
	for b := range numBatches {
		batch := make([]string, 0, batchSize)
		for i := b; i < count; i += numBatches {
			batch = append(batch, commits[i])
		}
		batches <- batch
	}
	close(batches)

	g, gctx := errgroup.WithContext(ctx)
	for range workers {
		g.Go(func() error {
			for batch := range batches {
				if err := gctx.Err(); err != nil {
					return err
				}
				if err := s.runWorkerCommits(gctx, yield, batch); err != nil {
					return err
				}
			}
			return nil
		})
	}

	return g.Wait()
}

// runSingleWorker runs one full, unpartitioned git log, used for the
// enumeration-failure fallback and when only one worker would run.
func (s *ParallelGit) runSingleWorker(ctx context.Context, yield FragmentsFunc) error {
	gitCmd, err := newGitLogCmd(ctx, s.RepoPath, s.LogOpts)
	if err != nil {
		return err
	}

	src := &Git{
		Cmd:             gitCmd,
		ShouldSkip:      s.ShouldSkip,
		Platform:        s.Platform,
		RemoteURL:       s.RemoteURL,
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
		ShouldSkip:      s.ShouldSkip,
		Platform:        s.Platform,
		RemoteURL:       s.RemoteURL,
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
		userArgs, err := splitGitLogOpts(logOpts)
		if err != nil {
			return nil, fmt.Errorf("invalid --log-opts: %w", err)
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
	cmd.Env = gitConfigIsolationEnv()
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
		repoPath:    repoPath,
	}, nil
}

// listCommits returns the commit SHAs matching logOpts from a single git
// rev-list invocation. When batched across workers, Fragments scans every
// returned SHA exactly once, so coverage depends only on the set being
// complete, not on its order.
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

// commitCount returns the number of commits matching the given log options.
func commitCount(ctx context.Context, source string, logOpts string) (int, error) {
	sourceClean := filepath.Clean(source)
	args := []string{"-C", sourceClean, "rev-list", "--count"}

	if logOpts != "" {
		userArgs, err := splitGitLogOpts(logOpts)
		if err != nil {
			return 0, fmt.Errorf("invalid --log-opts: %w", err)
		}
		args = append(args, userArgs...)
	} else {
		args = append(args, "--all")
	}

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = gitConfigIsolationEnv()
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("git rev-list --count: %w", err)
	}

	return strconv.Atoi(strings.TrimSpace(string(out)))
}
