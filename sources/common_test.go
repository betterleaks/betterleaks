package sources

import (
	"bufio"
	"bytes"
	"io"
	"math/rand"
	"strings"
	"testing"

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
			buf := make([]byte, 5, 25)
			n, err := c.r.Read(buf)
			require.NoError(t, err)

			// Act
			reader := bufio.NewReader(c.r)
			peekBuf, err := readUntilSafeBoundary(reader, buf[:n], n, 20)
			require.NoError(t, err)

			// Assert
			t.Log(string(peekBuf))
			require.Equal(t, c.expected, string(peekBuf))
		})
	}
}

// readUntilSafeBoundaryByteWise is the previous one-ReadByte-at-a-time
// implementation, kept as the oracle for the buffered version.
func readUntilSafeBoundaryByteWise(r *bufio.Reader, data []byte, initialSize int, maxPeekSize int) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	lastChar := data[len(data)-1]
	newlineCount := 0
	if isWhitespace[lastChar] {
		for i := len(data) - 1; i >= 0; i-- {
			lastChar = data[i]
			if lastChar == '\n' {
				newlineCount++
				if newlineCount >= 2 {
					return data, nil
				}
			} else if !isWhitespace[lastChar] {
				break
			}
		}
	}
	if maxPeekSize > 0 && cap(data)-len(data) < maxPeekSize {
		grown := make([]byte, len(data), len(data)+maxPeekSize)
		copy(grown, data)
		data = grown
	}
	newlineCount = 0
	for {
		lastChar = data[len(data)-1]
		if lastChar == '\n' {
			newlineCount++
			if newlineCount >= 2 {
				break
			}
		} else if !isWhitespace[lastChar] {
			newlineCount = 0
		}
		if (len(data) - initialSize) >= maxPeekSize {
			break
		}
		b, err := r.ReadByte()
		if err != nil {
			return data, err
		}
		data = append(data, b)
	}
	return data, nil
}

func Test_readUntilSafeBoundaryMatchesByteWise(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	alphabet := []byte("ab \t\r\n\n\n")
	for round := 0; round < 3000; round++ {
		n := rng.Intn(600)
		stream := make([]byte, n)
		for i := range stream {
			stream[i] = alphabet[rng.Intn(len(alphabet))]
		}
		initial := min(1+rng.Intn(64), n)
		if initial == 0 {
			continue
		}
		peek := rng.Intn(300)
		bufSize := 16 + rng.Intn(64)

		run := func(f func(*bufio.Reader, []byte, int, int) ([]byte, error)) (string, error, string) {
			r := bufio.NewReaderSize(bytes.NewReader(stream), bufSize)
			data := make([]byte, initial, initial+rng.Intn(2)*peek)
			_, _ = io.ReadFull(r, data)
			got, err := f(r, data, initial, peek)
			rest, _ := io.ReadAll(r)
			return string(got), err, string(rest)
		}
		want, wantErr, wantRest := run(readUntilSafeBoundaryByteWise)
		got, gotErr, gotRest := run(readUntilSafeBoundary)
		require.Equal(t, want, got, "stream=%q initial=%d peek=%d", stream, initial, peek)
		require.Equal(t, wantErr, gotErr, "error differs")
		require.Equal(t, wantRest, gotRest, "remaining stream differs")
	}
}
