package sources

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/require"
)

func Test_readUntilSafeBoundary(t *testing.T) {
	// Arrange
	cases := []struct {
		name     string
		r        io.Reader
		expected string
	}{
		// Current split is fine, exit early.
		{
			name:     "safe original split - LF",
			r:        strings.NewReader("abc\n\ndefghijklmnop\n\nqrstuvwxyz"),
			expected: "abc\n\n",
		},
		{
			name:     "safe original split - CRLF",
			r:        strings.NewReader("a\r\n\r\nbcdefghijklmnop\n"),
			expected: "a\r\n\r\n",
		},
		// Current split is bad, look for a better one.
		{
			name:     "safe split - LF",
			r:        strings.NewReader("abcdefg\nhijklmnop\n\nqrstuvwxyz"),
			expected: "abcdefg\nhijklmnop\n\n",
		},
		{
			name:     "safe split - CRLF",
			r:        strings.NewReader("abcdefg\r\nhijklmnop\r\n\r\nqrstuvwxyz"),
			expected: "abcdefg\r\nhijklmnop\r\n\r\n",
		},
		{
			name:     "safe split - blank line",
			r:        strings.NewReader("abcdefg\nhijklmnop\n\t  \t\nqrstuvwxyz"),
			expected: "abcdefg\nhijklmnop\n\t  \t\n",
		},
		// Current split is bad, exhaust options.
		{
			name:     "no safe split",
			r:        strings.NewReader("abcdefg\nhijklmnopqrstuvwxyz"),
			expected: "abcdefg\nhijklmnopqrstuvwx",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf := make([]byte, 5)
			n, err := c.r.Read(buf)
			require.NoError(t, err)

			// Act
			reader := bufio.NewReader(c.r)
			peekBuf := bytes.NewBuffer(buf[:n])
			err = readUntilSafeBoundary(reader, n, 20, peekBuf)
			require.NoError(t, err)

			// Assert
			t.Log(peekBuf.String())
			require.Equal(t, c.expected, peekBuf.String())
		})
	}
}

func TestReadUntilSafeBoundaryCompatibility(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alphabet := []byte{'a', 'b', 0, '\n', '\r', '\t', ' '}
	for i := 0; i < 2000; i++ {
		data := make([]byte, 1+rng.Intn(2000))
		for j := range data {
			data[j] = alphabet[rng.Intn(len(alphabet))]
		}
		initial := 1 + rng.Intn(len(data))
		limit := rng.Intn(1000)
		size := 16 + rng.Intn(128)
		expected, actual := bytes.NewBuffer(bytes.Clone(data[:initial])), bytes.NewBuffer(bytes.Clone(data[:initial]))
		oldReader := bufio.NewReaderSize(bytes.NewReader(data[initial:]), size)
		newReader := bufio.NewReaderSize(bytes.NewReader(data[initial:]), size)
		require.NoError(t, readUntilSafeBoundaryReference(oldReader, initial, limit, expected))
		require.NoError(t, readUntilSafeBoundary(newReader, initial, limit, actual))
		require.Equal(t, expected.Bytes(), actual.Bytes(), "case %d", i)
		oldRest, err := io.ReadAll(oldReader)
		require.NoError(t, err)
		newRest, err := io.ReadAll(newReader)
		require.NoError(t, err)
		require.Equal(t, oldRest, newRest, "case %d", i)
	}
}

func TestReadUntilSafeBoundaryReadErrors(t *testing.T) {
	readErr := errors.New("read failed")
	for _, tc := range []struct {
		name, content string
		limit         int
		wantErr       error
	}{
		{"error after data", strings.Repeat("x", 9000), maxPeekSize, readErr},
		{"boundary before error", "abc\n\n", maxPeekSize, nil},
		{"limit before error", strings.Repeat("x", 9000), 8000, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := func() *bufio.Reader {
				return bufio.NewReader(io.MultiReader(strings.NewReader(tc.content), iotest.ErrReader(readErr)))
			}
			expected, actual := bytes.NewBufferString("initial"), bytes.NewBufferString("initial")
			require.ErrorIs(t, readUntilSafeBoundaryReference(reader(), expected.Len(), tc.limit, expected), tc.wantErr)
			require.ErrorIs(t, readUntilSafeBoundary(reader(), actual.Len(), tc.limit, actual), tc.wantErr)
			require.Equal(t, expected.Bytes(), actual.Bytes())
		})
	}
}

func BenchmarkReadUntilSafeBoundary(b *testing.B) {
	for _, size := range []int{4096, 100000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			data := bytes.Repeat([]byte{'x'}, size+maxPeekSize)
			reader := bufio.NewReader(bytes.NewReader(nil))
			output := bytes.NewBuffer(make([]byte, 0, len(data)))
			for b.Loop() {
				reader.Reset(bytes.NewReader(data[size:]))
				output.Reset()
				output.Write(data[:size])
				if err := readUntilSafeBoundary(reader, size, maxPeekSize, output); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Frozen byte-at-a-time implementation protects existing fragment boundaries.
func readUntilSafeBoundaryReference(r *bufio.Reader, n int, maxPeekSize int, peekBuf *bytes.Buffer) error {
	if peekBuf.Len() == 0 {
		return nil
	}

	// Does the buffer end in consecutive newlines?
	var (
		data         = peekBuf.Bytes()
		lastChar     = data[len(data)-1]
		newlineCount = 0 // Tracks consecutive newlines
	)

	if isWhitespace[lastChar] {
		for i := len(data) - 1; i >= 0; i-- {
			lastChar = data[i]
			if lastChar == '\n' {
				newlineCount++

				// Stop if two consecutive newlines are found
				if newlineCount >= 2 {
					return nil
				}
			} else if isWhitespace[lastChar] {
				// The presence of other whitespace characters (`\r`, ` `, `\t`) shouldn't reset the count.
				// (Intentionally do nothing.)
			} else {
				break
			}
		}
	}

	// If not, read ahead until we (hopefully) find some.
	newlineCount = 0
	for {
		data = peekBuf.Bytes()
		// Check if the last character is a newline.
		lastChar = data[len(data)-1]
		if lastChar == '\n' {
			newlineCount++

			// Stop if two consecutive newlines are found
			if newlineCount >= 2 {
				break
			}
		} else if isWhitespace[lastChar] {
			// The presence of other whitespace characters (`\r`, ` `, `\t`) shouldn't reset the count.
			// (Intentionally do nothing.)
		} else {
			newlineCount = 0 // Reset if a non-newline character is found
		}

		// Stop growing the buffer if it reaches maxSize
		if (peekBuf.Len() - n) >= maxPeekSize {
			break
		}

		// Read additional data into a temporary buffer
		b, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		peekBuf.WriteByte(b)
	}
	return nil
}
