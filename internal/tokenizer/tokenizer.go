package tokenizer

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/base64"
	"fmt"
	"math"
	"sync"

	"github.com/dlclark/regexp2"
)

const (
	cl100KMergeableRanks = 100_256
	cl100KPattern        = `(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}{1,3}| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+`
	stackPieceBytes      = 128
)

//go:embed assets/cl100k_base.tiktoken.gz
var cl100KData []byte

var (
	defaultOnce    sync.Once
	defaultCounter *Counter
	defaultErr     error
)

// Counter counts cl100k_base tokens. It retains only the merge ranks and the
// expression used to split input; decoding and special-token state are omitted.
type Counter struct {
	ranks   map[string]uint32
	pattern *regexp2.Regexp
}

// Default returns the shared cl100k_base counter.
func Default() (*Counter, error) {
	defaultOnce.Do(func() {
		defaultCounter, defaultErr = New()
	})
	return defaultCounter, defaultErr
}

// New creates an independent cl100k_base counter from the embedded ranks.
func New() (*Counter, error) {
	ranks, err := loadRanks()
	if err != nil {
		return nil, err
	}
	pattern, err := regexp2.Compile(cl100KPattern, regexp2.None)
	if err != nil {
		return nil, fmt.Errorf("compile cl100k_base pattern: %w", err)
	}
	return &Counter{ranks: ranks, pattern: pattern}, nil
}

func loadRanks() (map[string]uint32, error) {
	gz, err := gzip.NewReader(bytes.NewReader(cl100KData))
	if err != nil {
		return nil, fmt.Errorf("open cl100k_base ranks: %w", err)
	}
	defer gz.Close()

	ranks := make(map[string]uint32, cl100KMergeableRanks)
	scanner := bufio.NewScanner(gz)
	var decoded []byte
	for scanner.Scan() {
		line := scanner.Bytes()
		separator := bytes.IndexByte(line, ' ')
		if separator <= 0 || separator == len(line)-1 {
			return nil, fmt.Errorf("parse cl100k_base rank %q", line)
		}

		decodedLen := base64.StdEncoding.DecodedLen(separator)
		if cap(decoded) < decodedLen {
			decoded = make([]byte, decodedLen)
		} else {
			decoded = decoded[:decodedLen]
		}
		n, err := base64.StdEncoding.Decode(decoded, line[:separator])
		if err != nil {
			return nil, fmt.Errorf("decode cl100k_base token: %w", err)
		}
		rank, err := parseRank(line[separator+1:])
		if err != nil {
			return nil, err
		}
		ranks[string(decoded[:n])] = rank
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read cl100k_base ranks: %w", err)
	}
	if len(ranks) != cl100KMergeableRanks {
		return nil, fmt.Errorf("cl100k_base has %d mergeable ranks, want %d", len(ranks), cl100KMergeableRanks)
	}
	return ranks, nil
}

func parseRank(value []byte) (uint32, error) {
	if len(value) == 0 {
		return 0, fmt.Errorf("parse empty cl100k_base rank")
	}
	var rank uint32
	for _, b := range value {
		if b < '0' || b > '9' {
			return 0, fmt.Errorf("parse cl100k_base rank %q", value)
		}
		digit := uint32(b - '0')
		if rank > (math.MaxUint32-digit)/10 {
			return 0, fmt.Errorf("cl100k_base rank %q overflows uint32", value)
		}
		rank = rank*10 + digit
	}
	return rank, nil
}

// Count returns the number of ordinary cl100k_base tokens in text. Betterleaks
// never enables special tokens, so treating their spelling as ordinary input is
// both intentional and equivalent to the previous tokenizer call.
func (c *Counter) Count(text string) int {
	if c == nil || c.pattern == nil || text == "" {
		return 0
	}

	// regexp2 reports rune indexes. Avoid constructing []rune for the overwhelmingly
	// common ASCII secrets, where rune and byte indexes are identical.
	ascii := true
	for i := 0; i < len(text); i++ {
		if text[i] >= 0x80 {
			ascii = false
			break
		}
	}
	var runes []rune
	if !ascii {
		runes = []rune(text)
	}

	count := 0
	match, _ := c.pattern.FindStringMatch(text)
	for match != nil {
		var piece string
		if ascii {
			piece = text[match.Index : match.Index+match.Length]
		} else {
			piece = string(runes[match.Index : match.Index+match.Length])
		}
		if _, ok := c.ranks[piece]; ok {
			count++
		} else {
			count += bytePairCount(piece, c.ranks)
		}
		match, _ = c.pattern.FindNextMatch(match)
	}
	return count
}

func bytePairCount(piece string, ranks map[string]uint32) int {
	if len(piece) < 2 {
		return len(piece)
	}

	boundaryCount := len(piece) + 1
	var local [stackPieceBytes + 1]int
	var boundaries []int
	if boundaryCount <= len(local) {
		boundaries = local[:boundaryCount]
	} else {
		boundaries = make([]int, boundaryCount)
	}
	for i := range boundaries {
		boundaries[i] = i
	}

	for len(boundaries) > 2 {
		minimumRank := uint32(math.MaxUint32)
		minimumIndex := -1
		for i := 0; i < len(boundaries)-2; i++ {
			rank, ok := ranks[piece[boundaries[i]:boundaries[i+2]]]
			if ok && rank < minimumRank {
				minimumRank = rank
				minimumIndex = i
			}
		}
		if minimumIndex < 0 {
			break
		}
		copy(boundaries[minimumIndex+1:], boundaries[minimumIndex+2:])
		boundaries = boundaries[:len(boundaries)-1]
	}
	return len(boundaries) - 1
}
