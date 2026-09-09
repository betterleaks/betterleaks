package sources

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/v2/internal/gitdiff"
)

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
	header, err := reader.ReadString('\n')
	if err != nil {
		return Fragment{}, err
	}
	fields := strings.Fields(header)
	if len(fields) != 3 || fields[1] != "commit" {
		return Fragment{}, fmt.Errorf("expected a commit object, received %q", strings.TrimSpace(header))
	}
	size, err := strconv.Atoi(fields[2])
	if err != nil || size < 0 {
		return Fragment{}, fmt.Errorf("invalid commit object size %q", fields[2])
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return Fragment{}, err
	}
	separator, err := reader.ReadByte()
	if err != nil {
		return Fragment{}, err
	}
	if separator != '\n' {
		return Fragment{}, fmt.Errorf("invalid commit object separator")
	}

	headers, message, ok := strings.Cut(string(data), "\n\n")
	if !ok {
		return Fragment{}, fmt.Errorf("commit %s has no message separator", fields[0])
	}
	attrs := map[string]string{
		AttrResource:   ResourceGitCommitMessage,
		AttrGitSHA:     fields[0],
		AttrGitMessage: message,
	}
	for _, line := range strings.Split(headers, "\n") {
		author, ok := strings.CutPrefix(line, "author ")
		if !ok {
			continue
		}
		end := strings.LastIndex(author, "> ")
		if end < 0 {
			return Fragment{}, fmt.Errorf("commit %s has an invalid author", fields[0])
		}
		identity, err := gitdiff.ParsePatchIdentity(author[:end+1])
		if err != nil {
			return Fragment{}, fmt.Errorf("parse commit author: %w", err)
		}
		date, err := gitdiff.ParsePatchDate(author[end+2:])
		if err != nil {
			return Fragment{}, fmt.Errorf("parse commit author date: %w", err)
		}
		attrs[AttrGitAuthorName] = identity.Name
		attrs[AttrGitAuthorEmail] = identity.Email
		attrs[AttrGitDate] = date.UTC().Format(time.RFC3339)
		break
	}
	return Fragment{Raw: message, StartLine: 1, Attributes: attrs}, nil
}
