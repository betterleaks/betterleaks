package sources

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/v2/internal/gitdiff"
)

// GitDiff scans additions from a caller-supplied git log -p or git diff stream.
// It never opens a repository or executes Git. Binary patches contain no
// scannable file content and are skipped. The caller owns and closes Content.
// As with Reader, cancellation cannot interrupt an arbitrary blocked Read.
type GitDiff struct {
	Content    io.Reader
	Attributes map[string]string
	Prefilter  PrefilterFunc
}

func (s *GitDiff) Fragments(ctx context.Context, yield FragmentsFunc) error {
	if s.Content == nil {
		return errors.New("git diff source requires input")
	}
	return readGitPatch(ctx, s.Content, func(file *gitdiff.File) (gitHunkFunc, error) {
		if file.IsDelete || file.IsBinary {
			return nil, nil
		}
		attrs := map[string]string{AttrPath: file.NewName, AttrResource: ResourceGitPatchContent}
		if p := file.PatchHeader; p != nil {
			attrs[AttrGitSHA], attrs[AttrGitMessage] = p.SHA, p.Message()
			if !p.AuthorDate.IsZero() {
				attrs[AttrGitDate] = p.AuthorDate.UTC().Format(time.RFC3339)
			}
			if p.Author != nil {
				attrs[AttrGitAuthorName], attrs[AttrGitAuthorEmail] = p.Author.Name, p.Author.Email
			}
		}
		maps.Copy(attrs, s.Attributes)
		if s.Prefilter != nil && s.Prefilter(attrs) {
			return nil, nil
		}
		return func(raw string, line int) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return yield(Fragment{Raw: raw, StartLine: line, Attributes: attrs}, nil)
		}, nil
	})
}

// gitHunkFunc accepts the added text of one hunk. Keeping hunk boundaries
// preserves multiline rules, decoding, and component proximity semantics.
type gitHunkFunc func(raw string, startLine int) error

// readGitPatch retains only the additions in the current hunk. The header
// callback runs before reading content and can return nil to discard a file.
// Header parsing stays with gitdiff for its quoted paths and metadata support;
// the hot path borrows reader buffers instead of allocating one object per line.
func readGitPatch(ctx context.Context, input io.Reader, header func(*gitdiff.File) (gitHunkFunc, error)) error {
	r := bufio.NewReaderSize(input, 64*1024)
	var preamble, fileHeader strings.Builder
	var content bytes.Buffer
	patch := &gitdiff.PatchHeader{}
	var consume gitHunkFunc
	var pending string
	var binaryPayload bool
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := pending
		pending = ""
		if line == "" {
			var err error
			line, err = r.ReadString('\n')
			if err != nil && err != io.EOF {
				return err
			}
			if line == "" {
				return nil
			}
		}
		if strings.HasPrefix(line, "\x1b[") {
			return errors.New("colored Git patches are unsupported; pass --no-color to the Git producer")
		}
		switch {
		case strings.HasPrefix(line, "diff --cc "), strings.HasPrefix(line, "diff --combined "):
			return errors.New("unsupported Git combined diff; use --diff-merges=first-parent or --diff-merges=separate")
		case strings.HasPrefix(line, "diff --git "):
			if strings.Contains(preamble.String(), "commit") {
				// Match gitdiff's handling of custom pretty formats: unrecognized
				// commit headers leave metadata unset.
				patch, _ = gitdiff.ParsePatchHeader(preamble.String())
			}
			preamble.Reset()
			fileHeader.Reset()
			fileHeader.WriteString(line)
			for {
				next, err := r.ReadString('\n')
				if err != nil && err != io.EOF {
					return err
				}
				if !gitFileHeaderLine(next) {
					pending = next
					break
				}
				fileHeader.WriteString(next)
			}
			file, err := parseGitScanHeader(fileHeader.String())
			if err != nil {
				return err
			}
			file.PatchHeader = patch
			file.IsBinary = strings.HasPrefix(pending, "Binary files ") || strings.HasPrefix(pending, "GIT binary patch")
			binaryPayload = file.IsBinary
			consume, err = header(file)
			if err != nil {
				return err
			}
		case strings.HasPrefix(line, "@@ -"):
			oldLines, newStart, newLines, err := gitHunkRange(line)
			if err != nil {
				return err
			}
			content.Reset()
			if err := readGitHunk(ctx, r, oldLines, newStart, newLines, consume, &content); err != nil {
				return err
			}
			// Do not retain an unusually large hunk for the rest of history.
			if content.Cap() > 1024*1024 {
				content = bytes.Buffer{}
			}
		case strings.HasPrefix(line, "commit"):
			binaryPayload = false
			preamble.Reset()
			preamble.WriteString(line)
		case strings.HasPrefix(line, "From "), strings.HasPrefix(line, "From:"):
			binaryPayload = false
			preamble.WriteString(line)
		default:
			// Preserve custom pretty-format preambles, without retaining
			// potentially large binary-patch payloads.
			if !binaryPayload {
				preamble.WriteString(line)
			}
		}
	}
}

func gitFileHeaderLine(line string) bool {
	for _, prefix := range []string{
		"--- ", "+++ ", "old mode ", "new mode ", "deleted file mode ",
		"new file mode ", "copy from ", "copy to ", "rename old ", "rename new ",
		"rename from ", "rename to ", "similarity index ", "dissimilarity index ", "index ",
	} {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

func parseGitScanHeader(header string) (*gitdiff.File, error) {
	// gitdiff mistakes a closing quote after an escaped backslash for an
	// escaped quote. Git always C-quotes backslashes in these filename fields;
	// the equivalent octal escape avoids that ambiguity without changing the
	// decoded name. This only touches metadata, never the file's contents.
	header = strings.ReplaceAll(header, "\\\\", "\\134")
	file, err := gitdiff.ParseFileHeader(header)
	if err != nil {
		return nil, fmt.Errorf("invalid Git file header: %w", err)
	}
	if file == nil {
		return nil, errors.New("invalid Git file header")
	}
	return file, nil
}

func gitHunkRange(header string) (oldLines, newStart, newLines int, err error) {
	fields := strings.Fields(header)
	if len(fields) < 4 || fields[0] != "@@" || fields[3] != "@@" || !strings.HasPrefix(fields[1], "-") || !strings.HasPrefix(fields[2], "+") {
		return 0, 0, 0, fmt.Errorf("invalid Git hunk header: %q", header)
	}
	parseRange := func(text string) (int, int, error) {
		startText, countText, hasCount := strings.Cut(text[1:], ",")
		start, err := strconv.Atoi(startText)
		if err != nil || start < 0 {
			return 0, 0, fmt.Errorf("invalid Git hunk range: %q", text)
		}
		count := 1
		if hasCount {
			count, err = strconv.Atoi(countText)
		}
		if err != nil || count < 0 {
			return 0, 0, fmt.Errorf("invalid Git hunk range: %q", text)
		}
		return start, count, nil
	}
	_, oldLines, err = parseRange(fields[1])
	if err != nil {
		return
	}
	newStart, newLines, err = parseRange(fields[2])
	return
}

func readGitHunk(ctx context.Context, r *bufio.Reader, oldLines, newStart, newLines int, consume gitHunkFunc, content *bytes.Buffer) error {
	keep := consume != nil
	line, runStart := newStart, newStart
	flush := func() error {
		if !keep || content.Len() == 0 {
			return nil
		}
		if err := consume(content.String(), runStart); err != nil {
			return err
		}
		content.Reset()
		return nil
	}
	var lastOp byte
	for oldLines > 0 || newLines > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		part, err := r.ReadSlice('\n')
		if len(part) == 0 {
			if err == io.EOF {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		op := part[0]
		switch op {
		case '+':
			if content.Len() == 0 {
				runStart = line
			}
			line++
			newLines--
		case '-':
			oldLines--
		case ' ', '\n':
			if err := flush(); err != nil {
				return err
			}
			line++
			oldLines--
			newLines--
		case '\\':
			if len(part) < 12 || !bytes.HasPrefix(part, []byte("\\ ")) {
				return errors.New("invalid Git no-newline marker")
			}
			if keep && lastOp == '+' && content.Len() > 0 {
				content.Truncate(content.Len() - 1)
			}
		default:
			return fmt.Errorf("invalid Git hunk line operation: %q", op)
		}
		if oldLines < 0 || newLines < 0 {
			return errors.New("Git hunk line count mismatch")
		}
		part = part[1:]
		for {
			if keep && op == '+' {
				content.Write(part)
			}
			if err != bufio.ErrBufferFull {
				break
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			part, err = r.ReadSlice('\n')
		}
		if err != nil && err != io.EOF {
			return err
		}
		lastOp = op
	}
	// The marker for the final line is outside the hunk's line counts.
	if marker, _ := r.Peek(2); bytes.Equal(marker, []byte("\\ ")) {
		if _, err := r.ReadString('\n'); err != nil && err != io.EOF {
			return err
		}
		if keep && lastOp == '+' && content.Len() > 0 {
			content.Truncate(content.Len() - 1)
		}
	}
	return flush()
}
