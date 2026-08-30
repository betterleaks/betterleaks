package sources

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gitleaks/go-gitdiff/gitdiff"
	"golang.org/x/sync/errgroup"

	"github.com/betterleaks/betterleaks/logging"
)

// fragmentsFromRepo partitions Git history across at most four processes.
// Each process consumes fragments serially; the detector provides the other
// half of the bounded jobs pipeline.
func (s *Git) fragmentsFromRepo(ctx context.Context, yield FragmentsFunc) error {
	jobs := jobsWithinBudget(s.Jobs, min(automaticJobs(), maxGitHistoryJobs), s.budget)
	historyJobs := min(jobs, maxGitHistoryJobs)

	repoSource := *s
	repoSource.Jobs = jobs

	if historyJobs <= 1 {
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
	if workers == 1 {
		return s.budget.run(ctx, func() error {
			return repoSource.runFullHistory(ctx, yield)
		})
	}

	chunkSize := (len(commits) + workers - 1) / workers
	logging.Debug().
		Int("commits", len(commits)).
		Int("workers", workers).
		Int("chunk_size", chunkSize).
		Msg("parallel git scan")

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
	cmd, err := NewGitLogCmdContext(ctx, s.RepoPath, s.LogOpts)
	if err != nil {
		return err
	}
	return s.runGitCmd(ctx, yield, cmd)
}

func (s *Git) runHistoryChunk(ctx context.Context, yield FragmentsFunc, commits []string) error {
	cmd, err := newGitLogCommitsCmd(ctx, s.RepoPath, commits)
	if err != nil {
		return err
	}
	return s.runGitCmd(ctx, yield, cmd)
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

// newGitLogCommitsCmd constructs a git log command for an exact set of
// commits. --no-walk keeps worker partitions deterministic and non-overlapping.
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
