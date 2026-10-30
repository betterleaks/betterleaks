package stream

import "bufio"

const maxPeekSize = 25 * 1_000 // 25 KB

var isWhitespace [256]bool

func init() {
	isWhitespace[' '] = true
	isWhitespace['\t'] = true
	isWhitespace['\n'] = true
	isWhitespace['\r'] = true
}

// readUntilSafeBoundary consumes r until it finds two consecutive `\n`
// characters, up to maxPeekSize bytes beyond initialSize. data must contain the
// initial read. Spare capacity is used for lookahead when available; otherwise
// the chunk grows once before any bytes are appended.
// EOF is returned with the final bytes so the caller need not read again.
// This hopefully avoids splitting. (https://github.com/gitleaks/gitleaks/issues/1651)
func readUntilSafeBoundary(r *bufio.Reader, data []byte, initialSize int, maxPeekSize int) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	// Does the buffer end in consecutive newlines?
	var (
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
					return data, nil
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
	if maxPeekSize > 0 && cap(data)-len(data) < maxPeekSize {
		grown := make([]byte, len(data), len(data)+maxPeekSize)
		copy(grown, data)
		data = grown
	}
	// Seed lookahead from only the final byte to preserve existing chunk boundaries.
	newlineCount = 0
	if data[len(data)-1] == '\n' {
		newlineCount = 1
	}
	for {
		budget := maxPeekSize - (len(data) - initialSize)
		if budget <= 0 {
			return data, nil
		}
		// Inspect available bytes without waiting for a full buffer from a
		// streaming reader. Request one byte to refill an empty buffer.
		peek, err := r.Peek(min(budget, max(1, r.Buffered())))
		consumed := 0
		found := false
		for _, b := range peek {
			consumed++
			if b == '\n' {
				newlineCount++
				if newlineCount >= 2 {
					found = true
					break
				}
			} else if !isWhitespace[b] {
				newlineCount = 0
			}
		}
		data = append(data, peek[:consumed]...)
		if _, discardErr := r.Discard(consumed); discardErr != nil {
			return data, discardErr
		}
		if found {
			return data, nil
		}
		if err != nil {
			return data, err
		}
	}
}
