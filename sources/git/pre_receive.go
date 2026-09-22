package git

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
)

const zeroOID = "0000000000000000000000000000000000000000"

// PreReceiveRefUpdate is a ref update read from a pre-receive hook's stdin.
type PreReceiveRefUpdate struct {
	OldValue string
	NewValue string
	RefName  string
}

func isZeroOID(value string) bool {
	if value == "" {
		return true
	}
	for _, r := range value {
		if r != '0' {
			return false
		}
	}
	return true
}

func isHexOID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func (u PreReceiveRefUpdate) IsDelete() bool { return isZeroOID(u.NewValue) }
func (u PreReceiveRefUpdate) IsCreate() bool { return isZeroOID(u.OldValue) }

// ParsePreReceiveInput parses "<old-value> <new-value> <ref-name>" lines.
func ParsePreReceiveInput(r io.Reader) ([]PreReceiveRefUpdate, error) {
	var updates []PreReceiveRefUpdate
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		updates = append(updates, PreReceiveRefUpdate{
			OldValue: fields[0],
			NewValue: fields[1],
			RefName:  strings.Join(fields[2:], " "),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return updates, nil
}

// CommitResolver peels an object ID to a commit ID. A false result without an
// error means the object exists but does not point at a commit.
type CommitResolver func(oid string) (string, bool, error)

// PreReceiveLogArgs returns git revision arguments selecting newly pushed commits.
func PreReceiveLogArgs(updates []PreReceiveRefUpdate, resolve CommitResolver) ([]string, error) {
	var args []string
	hasUnboundedUpdate := false
	for _, update := range updates {
		if update.IsDelete() || !isHexOID(update.NewValue) {
			continue
		}
		if !update.IsCreate() && !isHexOID(update.OldValue) {
			continue
		}

		newValue := update.NewValue
		if resolve != nil {
			commit, ok, err := resolve(update.NewValue)
			if err != nil {
				return nil, fmt.Errorf("resolve new value for %s: %w", update.RefName, err)
			}
			if !ok {
				continue
			}
			newValue = commit
		}

		if update.IsCreate() {
			args = append(args, newValue)
			hasUnboundedUpdate = true
			continue
		}

		oldValue := update.OldValue
		if resolve != nil {
			commit, ok, err := resolve(update.OldValue)
			if err != nil {
				return nil, fmt.Errorf("resolve old value for %s: %w", update.RefName, err)
			}
			if !ok {
				args = append(args, newValue)
				hasUnboundedUpdate = true
				continue
			}
			oldValue = commit
		}
		args = append(args, oldValue+".."+newValue)
	}
	if hasUnboundedUpdate {
		args = append(args, "--not", "--all")
	}
	return args, nil
}

// NewGitCommitResolver resolves commits and annotated tags in repoPath.
func NewGitCommitResolver(ctx context.Context, repoPath string) CommitResolver {
	repoPath = filepath.Clean(repoPath)
	return func(oid string) (string, bool, error) {
		if !isHexOID(oid) {
			return "", false, fmt.Errorf("invalid object ID %q", oid)
		}

		peeled := oid + "^{}"
		cmd := exec.CommandContext(ctx, "git", "-C", repoPath, "cat-file", "-t", peeled)
		out, err := cmd.Output()
		if err != nil {
			return "", false, fmt.Errorf("inspect object %s: %w", oid, err)
		}
		if strings.TrimSpace(string(out)) != "commit" {
			return "", false, nil
		}

		cmd = exec.CommandContext(ctx, "git", "-C", repoPath,
			"rev-parse", "--verify", "--quiet", "--end-of-options", peeled)
		out, err = cmd.Output()
		if err != nil {
			return "", false, fmt.Errorf("peel commit %s: %w", oid, err)
		}
		commit := strings.TrimSpace(string(out))
		if !isHexOID(commit) {
			return "", false, fmt.Errorf("git returned invalid commit ID %q", commit)
		}
		return commit, true, nil
	}
}
