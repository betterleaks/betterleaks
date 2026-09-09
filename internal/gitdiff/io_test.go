package gitdiff

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"testing"
)

func TestLineReaderAt(t *testing.T) {
	const lineTemplate = "generated test line %d\n"

	tests := map[string]struct {
		InputLines int
		Offset     int64
		Count      int
		Err        bool
		EOF        bool
		EOFCount   int
	}{
		"readLines": {
			InputLines: 32,
			Offset:     0,
			Count:      4,
		},
		"readLinesOffset": {
			InputLines: 32,
			Offset:     8,
			Count:      4,
		},
		"readLinesLargeOffset": {
			InputLines: 8192,
			Offset:     4096,
			Count:      64,
		},
		"readSingleLine": {
			InputLines: 4,
			Offset:     2,
			Count:      1,
		},
		"readZeroLines": {
			InputLines: 4,
			Offset:     2,
			Count:      0,
		},
		"readAllLines": {
			InputLines: 64,
			Offset:     0,
			Count:      64,
		},
		"readThroughEOF": {
			InputLines: 16,
			Offset:     12,
			Count:      8,
			EOF:        true,
			EOFCount:   4,
		},
		"emptyInput": {
			InputLines: 0,
			Offset:     0,
			Count:      2,
			EOF:        true,
			EOFCount:   0,
		},
		"offsetAfterEOF": {
			InputLines: 8,
			Offset:     10,
			Count:      2,
			EOF:        true,
			EOFCount:   0,
		},
		"offsetNegative": {
			InputLines: 8,
			Offset:     -1,
			Count:      2,
			Err:        true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var input bytes.Buffer
			for i := 0; i < test.InputLines; i++ {
				fmt.Fprintf(&input, lineTemplate, i)
			}

			output := make([][]byte, test.Count)
			for i := 0; i < test.Count; i++ {
				output[i] = []byte(fmt.Sprintf(lineTemplate, test.Offset+int64(i)))
			}

			r := &lineReaderAt{r: bytes.NewReader(input.Bytes())}
			lines := make([][]byte, test.Count)

			n, err := r.ReadLinesAt(lines, test.Offset)
			if test.Err {
				if err == nil {
					t.Fatal("expected error reading lines, but got nil")
				}
				return
			}
			if err != nil && (!test.EOF || err != io.EOF) {
				t.Fatalf("unexpected error reading lines: %v", err)
			}

			count := test.Count
			if test.EOF {
				count = test.EOFCount
			}

			if n != count {
				t.Fatalf("incorrect number of lines read: expected %d, actual %d", count, n)
			}
			for i := 0; i < n; i++ {
				if !bytes.Equal(output[i], lines[i]) {
					t.Errorf("incorrect content in line %d:\nexpected: %q\nactual: %q", i, output[i], lines[i])
				}
			}
		})
	}

	newlineTests := map[string]struct {
		InputSize int
	}{
		"readLinesNoFinalNewline": {
			InputSize: indexBufferSize + indexBufferSize/2,
		},
		"readLinesNoFinalNewlineBufferMultiple": {
			InputSize: 4 * indexBufferSize,
		},
	}

	for name, test := range newlineTests {
		t.Run(name, func(t *testing.T) {
			input := bytes.Repeat([]byte("0"), test.InputSize)

			var output [][]byte
			for i := 0; i < len(input); i++ {
				last := i
				i += rand.Intn(80)
				if i < len(input)-1 { // last character of input must not be a newline
					input[i] = '\n'
					output = append(output, input[last:i+1])
				} else {
					output = append(output, input[last:])
				}
			}

			r := &lineReaderAt{r: bytes.NewReader(input)}
			lines := make([][]byte, len(output))

			n, err := r.ReadLinesAt(lines, 0)
			if err != nil {
				t.Fatalf("unexpected error reading reading lines: %v", err)
			}

			if n != len(output) {
				t.Fatalf("incorrect number of lines read: expected %d, actual %d", len(output), n)
			}

			for i, line := range lines {
				if !bytes.Equal(output[i], line) {
					t.Errorf("incorrect content in line %d:\nexpected: %q\nactual: %q", i, output[i], line)
				}
			}
		})
	}
}

func TestCopyFrom(t *testing.T) {
	tests := map[string]struct {
		Bytes  int64
		Offset int64
	}{
		"copyAll": {
			Bytes: byteBufferSize / 2,
		},
		"copyPartial": {
			Bytes:  byteBufferSize / 2,
			Offset: byteBufferSize / 4,
		},
		"copyLarge": {
			Bytes: 8 * byteBufferSize,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			data := make([]byte, test.Bytes)
			rand.Read(data)

			var dst bytes.Buffer
			n, err := copyFrom(&dst, bytes.NewReader(data), test.Offset)
			if err != nil {
				t.Fatalf("unexpected error copying data: %v", err)
			}
			if n != test.Bytes-test.Offset {
				t.Fatalf("incorrect number of bytes copied: expected %d, actual %d", test.Bytes-test.Offset, n)
			}

			expected := data[test.Offset:]
			if !bytes.Equal(expected, dst.Bytes()) {
				t.Fatalf("incorrect data copied:\nexpected: %v\nactual: %v", expected, dst.Bytes())
			}
		})
	}
}

func TestCopyLinesFrom(t *testing.T) {
	tests := map[string]struct {
		Lines  int64
		Offset int64
	}{
		"copyAll": {
			Lines: lineBufferSize / 2,
		},
		"copyPartial": {
			Lines:  lineBufferSize / 2,
			Offset: lineBufferSize / 4,
		},
		"copyLarge": {
			Lines: 8 * lineBufferSize,
		},
	}

	const lineLength = 128

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			data := make([]byte, test.Lines*lineLength)
			for i := range data {
				data[i] = byte(32 + rand.Intn(95)) // ascii letters, numbers, symbols
				if i%lineLength == lineLength-1 {
					data[i] = '\n'
				}
			}

			var dst bytes.Buffer
			n, err := copyLinesFrom(&dst, &lineReaderAt{r: bytes.NewReader(data)}, test.Offset)
			if err != nil {
				t.Fatalf("unexpected error copying data: %v", err)
			}
			if n != test.Lines-test.Offset {
				t.Fatalf("incorrect number of lines copied: expected %d, actual %d", test.Lines-test.Offset, n)
			}

			expected := data[test.Offset*lineLength:]
			if !bytes.Equal(expected, dst.Bytes()) {
				t.Fatalf("incorrect data copied:\nexpected: %v\nactual: %v", expected, dst.Bytes())
			}
		})
	}
}
