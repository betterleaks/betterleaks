package sources

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources/scm"
)

// ParallelGit scans a git repo with multiple `git log -p` processes. A single
// streaming `git rev-list` distributes each commit to exactly one worker, so
// the parent process does not retain the repository's entire SHA list.
type ParallelGit struct {
	RepoPath        string
	ShouldSkip      SkipFunc
	Platform        scm.Platform
	RemoteURL       string
	MaxArchiveDepth int
	LogOpts         string
	Workers         int // 0 means auto (min(NumCPU, 4))
}

func (s *ParallelGit) workers() int {
	if s.Workers > 0 {
		return s.Workers
	}
	return max(min(runtime.NumCPU(), 4), 1)
}

// Fragments implements Source by partitioning commits across
// multiple parallel git log workers.
func (s *ParallelGit) Fragments(ctx context.Context, yield FragmentsFunc) error {
	if s == nil {
		return errors.New("sources: parallel git source is required")
	}
	if yield == nil {
		return errors.New("sources: git fragment callback is required")
	}
	workers := s.workers()
	if workers <= 1 {
		return s.runSingleWorker(ctx, yield)
	}
	if strings.TrimSpace(s.LogOpts) != "" {
		// Arbitrary git-log options can contain pathspecs, pickaxe filters, or
		// revision syntax that cannot be reproduced by partitioning bare SHAs.
		logging.Debug().Msg("using one git worker because --log-opts cannot be partitioned safely")
		return s.runSingleWorker(ctx, yield)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	commitCount, err := gitCommitCount(ctx, s.RepoPath)
	if err != nil {
		return err
	}
	if commitCount == 0 {
		return nil
	}
	workers = min(workers, commitCount)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type worker struct {
		source *Git
		stdin  io.WriteCloser
	}
	started := make([]worker, 0, workers)
	for range workers {
		gitCmd, stdin, err := newGitLogStdinCmd(runCtx, s.RepoPath)
		if err != nil {
			cancel()
			for _, worker := range started {
				_ = worker.stdin.Close()
				worker.source.Cmd.cancelAndDrain()
				_ = worker.source.Cmd.Wait()
			}
			return err
		}
		started = append(started, worker{
			stdin: stdin,
			source: &Git{
				Cmd:             gitCmd,
				ShouldSkip:      s.ShouldSkip,
				Platform:        s.Platform,
				RemoteURL:       s.RemoteURL,
				MaxArchiveDepth: s.MaxArchiveDepth,
			},
		})
	}

	chunkSize := (commitCount + workers - 1) / workers
	logging.Info().
		Int("commits", commitCount).
		Int("workers", workers).
		Int("chunk_size", chunkSize).
		Msg("parallel git scan")

	g, gctx := errgroup.WithContext(runCtx)
	for _, worker := range started {
		g.Go(func() error {
			return worker.source.Fragments(gctx, yield)
		})
	}
	g.Go(func() error {
		writers := make([]io.WriteCloser, len(started))
		for i := range started {
			writers[i] = started[i].stdin
		}
		return streamGitCommits(gctx, s.RepoPath, writers, chunkSize)
	})

	return g.Wait()
}

func gitCommitCount(ctx context.Context, source string) (int, error) {
	sourceClean := filepath.Clean(source)
	cmd := exec.CommandContext(ctx, "git", "-C", sourceClean, "rev-list", "--count", "--all")
	cmd.Env = gitConfigIsolationEnv()
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("git rev-list --count: %w: %s", err, strings.TrimSpace(string(output)))
	}
	count, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil {
		return 0, fmt.Errorf("parse git rev-list --count output: %w", err)
	}
	return count, nil
}

// runSingleWorker runs a full git log (no partitioning) for small repos or
// single-worker mode.
func (s *ParallelGit) runSingleWorker(ctx context.Context, yield FragmentsFunc) error {
	gitCmd, err := NewGitLogCmd(ctx, s.RepoPath, s.LogOpts)
	if err != nil {
		return err
	}

	src := &Git{
		Cmd:             gitCmd,
		ShouldSkip:      s.ShouldSkip,
		Platform:        s.Platform,
		RemoteURL:       s.RemoteURL,
		MaxArchiveDepth: s.MaxArchiveDepth,
	}

	return src.Fragments(ctx, yield)
}

func newGitLogStdinCmd(ctx context.Context, source string) (*GitCmd, io.WriteCloser, error) {
	sourceClean := filepath.Clean(source)
	args := []string{"-C", sourceClean, "log", "-p", "-U0", "--no-walk", "--stdin", "--diff-filter=tuxdb"}
	return startGitCmdWithStdin(ctx, sourceClean, args)
}

func streamGitCommits(ctx context.Context, source string, writers []io.WriteCloser, chunkSize int) (returnErr error) {
	defer func() {
		for i, writer := range writers {
			if writer != nil {
				if err := writer.Close(); err != nil {
					returnErr = errors.Join(returnErr, fmt.Errorf("close git worker %d stdin: %w", i, err))
				}
			}
		}
	}()
	if len(writers) == 0 {
		return nil
	}

	sourceClean := filepath.Clean(source)
	cmd := exec.CommandContext(ctx, "git", "-C", sourceClean, "rev-list", "--all")
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

	abort := func(err error) error {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		return err
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 128), 1024*1024)
	next := 0
	writtenToCurrent := 0
	for scanner.Scan() {
		if _, err := fmt.Fprintln(writers[next], scanner.Text()); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return abort(ctxErr)
			}
			return abort(fmt.Errorf("write commit to git worker: %w", err))
		}
		writtenToCurrent++
		if writtenToCurrent >= chunkSize && next+1 < len(writers) {
			// This worker has its complete contiguous history range. Closing its
			// stdin lets Git begin emitting patches while rev-list streams the
			// remaining ranges to later workers.
			closeErr := writers[next].Close()
			writers[next] = nil
			if closeErr != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return abort(ctxErr)
				}
				return abort(fmt.Errorf("close git worker %d stdin: %w", next, closeErr))
			}
			next++
			writtenToCurrent = 0
		}
	}
	if err := scanner.Err(); err != nil {
		return abort(fmt.Errorf("read git rev-list: %w", err))
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("git rev-list: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
