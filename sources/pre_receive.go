package sources

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
)

// zeroOID is the all-zero object id git uses to represent a missing ref
// (a created or deleted ref) in pre-receive/update hook input.
const zeroOID = "0000000000000000000000000000000000000000"

// PreReceiveRefUpdate is a single ref update as reported to a pre-receive hook
// on stdin in the form "<old-value> SP <new-value> SP <ref-name> LF".
type PreReceiveRefUpdate struct {
	OldValue string
	NewValue string
	RefName  string
}

// isZeroOID reports whether value is git's all-zero object id (any length,
// to tolerate both SHA-1 and SHA-256 repositories).
func isZeroOID(value string) bool {
	if value == "" {
		return true
	}
	if value == zeroOID {
		return true
	}
	for _, r := range value {
		if r != '0' {
			return false
		}
	}
	return true
}

// isHexOID reports whether value is a syntactically valid git object id: a
// lowercase or uppercase hex string of SHA-1 (40) or SHA-256 (64) length.
// Ref updates read from hook stdin are untrusted, so validating them before
// they are passed to git rejects option- or revision-injection attempts (for
// example a value beginning with "-" or containing ".." or "^") and any other
// non-object-id input.
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

// IsDelete reports whether the update deletes the ref (new value is zero).
func (u PreReceiveRefUpdate) IsDelete() bool { return isZeroOID(u.NewValue) }

// IsCreate reports whether the update creates the ref (old value is zero).
func (u PreReceiveRefUpdate) IsCreate() bool { return isZeroOID(u.OldValue) }

// ParsePreReceiveInput parses the ref updates a pre-receive hook receives on
// stdin. Each non-empty line must contain three whitespace-separated fields:
// old-value, new-value, and ref-name. Blank lines are ignored.
func ParsePreReceiveInput(r io.Reader) ([]PreReceiveRefUpdate, error) {
	var updates []PreReceiveRefUpdate
	scanner := bufio.NewScanner(r)
	// Ref update lines are short, but raise the buffer to be safe with long
	// ref names.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
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

// CommitResolver peels a ref object id to the commit it points at. It returns
// the resolved commit id and true when the object is (or peels to) a commit,
// and false when it does not — for example a tag that points directly at a
// tree or blob, which has no commit history to scan.
type CommitResolver func(oid string) (string, bool)

// PreReceiveLogArgs converts ref updates into `git log` revision arguments that
// select only the newly pushed commits.
//
//   - Deleted refs (new value is zero) contribute nothing.
//   - Updated refs contribute "<old>..<new>".
//   - Created refs (old value is zero) contribute "<new>" together with a
//     single trailing "--not --all", which excludes every commit already
//     reachable from an existing ref so only genuinely new commits are scanned.
//
// resolve peels each old and new value to a commit. Ref updates whose new value
// does not resolve to a commit (for example a tag pointing at a tree or blob)
// are skipped so their object ids are never handed to `git log`. If only the
// old value fails to resolve — a ref retagged from a non-commit target to a
// commit — the update is scanned like a create ("<new>" bounded by
// "--not --all") rather than emitting an invalid "<old>..<new>" range. When
// resolve is nil the values are used verbatim.
//
// The returned slice is empty when there is nothing to scan (for example a
// push that only deletes refs).
func PreReceiveLogArgs(updates []PreReceiveRefUpdate, resolve CommitResolver) []string {
	var (
		args      []string
		hasCreate bool
	)
	for _, u := range updates {
		if u.IsDelete() {
			continue
		}
		// Reject updates whose object ids are not syntactically valid so no
		// attacker-controlled value from hook stdin can reach git as an
		// option or revision expression.
		if !isHexOID(u.NewValue) {
			continue
		}
		if !u.IsCreate() && !isHexOID(u.OldValue) {
			continue
		}

		newValue := u.NewValue
		if resolve != nil {
			commit, ok := resolve(u.NewValue)
			if !ok {
				// The pushed ref does not point at a commit; there is no
				// history to scan.
				continue
			}
			newValue = commit
		}

		// A create has no old commit to bound the range, so scan the new
		// commit and exclude existing history below via "--not --all".
		if u.IsCreate() {
			args = append(args, newValue)
			hasCreate = true
			continue
		}

		// For an update, bound the scan with "<old>..<new>". The old value
		// must also peel to a commit — a ref retagged from a non-commit
		// (blob/tree) target to a commit would otherwise hand a non-commit id
		// to git log and fail the scan. When the old value is not a commit,
		// fall back to scanning just the new commit excluding existing
		// history, exactly as for a create.
		oldValue := u.OldValue
		if resolve != nil {
			commit, ok := resolve(u.OldValue)
			if !ok {
				args = append(args, newValue)
				hasCreate = true
				continue
			}
			oldValue = commit
		}
		args = append(args, oldValue+".."+newValue)
	}
	if hasCreate {
		// Exclude commits already present in the repository so a newly created
		// branch or tag is not scanned back to the root commit.
		args = append(args, "--not", "--all")
	}
	return args
}

// NewGitCommitResolver returns a CommitResolver backed by `git rev-parse` in
// the given repository. An object id resolves when it peels to a commit
// (`<oid>^{commit}`), which handles both plain commits and annotated tags that
// target a commit. Tags that point directly at a tree or blob do not peel and
// are reported as non-commits.
//
// The object id is validated as hex before use, so the value handed to git can
// never be interpreted as an option or a broader revision expression even
// though it originates from untrusted hook stdin.
func NewGitCommitResolver(ctx context.Context, repoPath string) CommitResolver {
	sourceClean := filepath.Clean(repoPath)
	return func(oid string) (string, bool) {
		if !isHexOID(oid) {
			return "", false
		}
		cmd := exec.CommandContext(ctx, "git", "-C", sourceClean,
			"rev-parse", "--verify", "--quiet", "--end-of-options", oid+"^{commit}")
		cmd.Env = gitConfigIsolationEnv()
		out, err := cmd.Output()
		if err != nil {
			return "", false
		}
		commit := strings.TrimSpace(string(out))
		if commit == "" {
			return "", false
		}
		return commit, true
	}
}
