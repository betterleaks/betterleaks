package sources

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/gitleaks/go-gitdiff/gitdiff"
	"golang.org/x/sync/errgroup"

	"github.com/betterleaks/betterleaks/logging"
)

// historyFragments opens the repository once. Parallel scans enumerate commits
// once, then partition those SHAs into non-overlapping git log workers.
func (s *Git) historyFragments(ctx context.Context, yield FragmentsFunc) error {
	source := s.RepoPath
	if source == "" {
		source = "."
	}
	repo, err := openGitRepo(ctx, source, GitOptions{TrustLocalGitConfig: s.TrustLocalGitConfig}, false)
	if err != nil {
		return err
	}
	// Each worker's Fragments returns only after its blob readers close.
	defer repo.Close()

	if s.Workers <= 1 {
		return s.runSingleWorker(ctx, repo, yield)
	}

	commits, err := listCommits(ctx, repo, s.LogOpts)
	if err != nil {
		return fmt.Errorf("list commits: %w", err)
	}

	count := len(commits)
	workers := s.Workers
	if count == 0 {
		return nil
	}
	if workers > count {
		workers = count
	}

	// For very small repos, just run a single worker (no overhead)
	if workers <= 1 {
		return s.runSingleWorker(ctx, repo, yield)
	}

	chunkSize := (count + workers - 1) / workers
	logging.Info().Int("commits", count).Int("workers", workers).Int("chunk_size", chunkSize).Msg("parallel git scan")

	g, gctx := errgroup.WithContext(ctx)
	for i := range workers {
		start := i * chunkSize
		if start >= count {
			break
		}
		end := min(start+chunkSize, count)
		chunk := commits[start:end]
		g.Go(func() error {
			return s.runWorkerCommits(gctx, repo, yield, chunk)
		})
	}

	return g.Wait()
}

// runSingleWorker runs a full git log (no partitioning) for small repos or
// single-worker mode.
func (s *Git) runSingleWorker(ctx context.Context, repo *gitRepo, yield FragmentsFunc) error {
	gitCmd, err := newGitLogCmd(ctx, repo, s.LogOpts)
	if err != nil {
		return err
	}

	return s.fragmentsFromCmd(ctx, gitCmd, yield)
}

// runWorkerCommits runs a git log process for a specific set of commit SHAs,
// piped via stdin with --no-walk.
func (s *Git) runWorkerCommits(ctx context.Context, repo *gitRepo, yield FragmentsFunc, commits []string) error {
	gitCmd, err := newGitLogCommitsCmd(ctx, repo, commits, s.LogOpts)
	if err != nil {
		return err
	}

	return s.fragmentsFromCmd(ctx, gitCmd, yield)
}

// newGitLogCmd constructs a full git log -p command (no partitioning).
func newGitLogCmd(ctx context.Context, repo *gitRepo, logOpts string) (*GitCmd, error) {
	args := []string{"log", "-p", "-U0", "--diff-merges=first-parent"}

	if logOpts != "" {
		userArgs, err := splitGitLogOpts(logOpts)
		if err != nil {
			return nil, fmt.Errorf("invalid --log-opts: %w", err)
		}
		args = append(args, userArgs...)
	} else {
		args = append(args, "--full-history", "--all", "--diff-filter=tuxdb")
	}

	return startGitLogCmd(ctx, repo, args)
}

// newGitLogCommitsCmd constructs a git log -p command that processes a specific
// set of commits via --no-walk --stdin. This avoids non-deterministic ordering
// issues with --skip/--max-count on repos with timestamp ties.
func newGitLogCommitsCmd(ctx context.Context, repo *gitRepo, commits []string, logOpts string) (*GitCmd, error) {
	args := []string{"log", "-p", "-U0", "--diff-merges=first-parent", "--no-walk", "--stdin", "--diff-filter=tuxdb"}
	userArgs, err := splitGitLogOpts(logOpts)
	if err != nil {
		return nil, fmt.Errorf("invalid --log-opts: %w", err)
	}
	for i, arg := range userArgs {
		if arg == "--" {
			// rev-list filters commits; workers must also filter their patches.
			args = append(args, userArgs[i:]...)
			break
		}
	}

	return startGitCmd(ctx, repo, args, strings.NewReader(strings.Join(commits, "\n")+"\n"))
}

// startGitLogCmd is the shared tail for starting a git log process, wiring up
// stdout/stderr pipes, and returning a GitCmd.
func startGitLogCmd(ctx context.Context, repo *gitRepo, args []string) (*GitCmd, error) {
	return startGitCmd(ctx, repo, args, nil)
}

func startGitCmd(ctx context.Context, repo *gitRepo, args []string, stdin io.Reader) (*GitCmd, error) {
	cmd := repo.command(ctx, args...)
	cmd.Stdin = stdin
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
		_ = cmd.Process.Kill()
		for range errCh {
		}
		_ = cmd.Wait()
		return nil, err
	}

	return &GitCmd{
		cmd:         cmd,
		diffFilesCh: gitdiffFiles,
		errCh:       errCh,
		repo:        repo,
	}, nil
}

// listCommits returns all commit SHAs matching the given log options.
// The order is deterministic for a given repo state (reverse chronological
// from a single rev-list invocation), which is critical for correct
// partitioning across workers.
func listCommits(ctx context.Context, repo *gitRepo, logOpts string) ([]string, error) {
	args := []string{"rev-list"}

	if logOpts != "" {
		userArgs, err := splitGitLogOpts(logOpts)
		if err != nil {
			return nil, fmt.Errorf("invalid --log-opts: %w", err)
		}
		args = append(args, userArgs...)
	} else {
		args = append(args, "--all")
	}

	out, err := repo.command(ctx, args...).Output()
	if err != nil {
		return nil, fmt.Errorf("git rev-list: %w", err)
	}

	text := strings.TrimSpace(string(out))
	if text == "" {
		return nil, nil
	}
	return strings.Split(text, "\n"), nil
}
