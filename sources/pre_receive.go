package sources

import (
	"bufio"
	"io"
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

// PreReceiveLogArgs converts ref updates into `git log` revision arguments that
// select only the newly pushed commits.
//
//   - Deleted refs (new value is zero) contribute nothing.
//   - Updated refs contribute "<old>..<new>".
//   - Created refs (old value is zero) contribute "<new>" together with a
//     single trailing "--not --all", which excludes every commit already
//     reachable from an existing ref so only genuinely new commits are scanned.
//
// The returned slice is empty when there is nothing to scan (for example a
// push that only deletes refs).
func PreReceiveLogArgs(updates []PreReceiveRefUpdate) []string {
	var (
		args      []string
		hasCreate bool
	)
	for _, u := range updates {
		if u.IsDelete() {
			continue
		}
		if u.IsCreate() {
			args = append(args, u.NewValue)
			hasCreate = true
			continue
		}
		args = append(args, u.OldValue+".."+u.NewValue)
	}
	if hasCreate {
		// Exclude commits already present in the repository so a newly created
		// branch or tag is not scanned back to the root commit.
		args = append(args, "--not", "--all")
	}
	return args
}
