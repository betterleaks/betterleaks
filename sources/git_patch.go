package sources

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/betterleaks/betterleaks/v2/internal/gitdiff"
)

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
		switch {
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
			if err := readGitHunk(ctx, r, oldLines, newLines, consume != nil, &content); err != nil {
				return err
			}
			if consume != nil {
				// One exact-sized copy detaches the yielded string from the
				// reusable buffer, including when detection is asynchronous.
				if err := consume(content.String(), newStart); err != nil {
					return err
				}
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

func readGitHunk(ctx context.Context, r *bufio.Reader, oldLines, newLines int, keep bool, content *bytes.Buffer) error {
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
			newLines--
		case '-':
			oldLines--
		case ' ', '\n':
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
	return nil
}

// addedGitLines avoids geometric string growth for the compatibility API.
func addedGitLines(fragment *gitdiff.TextFragment) string {
	var size int
	for _, line := range fragment.Lines {
		if line.Op == gitdiff.OpAdd {
			size += len(line.Line)
		}
	}
	var raw strings.Builder
	raw.Grow(size)
	for _, line := range fragment.Lines {
		if line.Op == gitdiff.OpAdd {
			raw.WriteString(line.Line)
		}
	}
	return raw.String()
}
