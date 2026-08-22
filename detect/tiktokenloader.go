package detect

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/pkoukk/tiktoken-go"
)

//go:embed assets/cl100k_base.tiktoken.gz
var bpeData []byte

const cl100kPattern = `(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}{1,3}| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+`

// newEmbeddedTokenizer constructs cl100k_base without changing tiktoken-go's
// process-global BPE loader. Betterleaks is a library as well as a command; a
// detector must not alter tokenizer behavior for unrelated code in its host.
func newEmbeddedTokenizer() (*tiktoken.Tiktoken, error) {
	ranks, err := loadEmbeddedBPERanks()
	if err != nil {
		return nil, err
	}
	specialTokens := map[string]int{
		tiktoken.ENDOFTEXT:   100257,
		tiktoken.FIM_PREFIX:  100258,
		tiktoken.FIM_MIDDLE:  100259,
		tiktoken.FIM_SUFFIX:  100260,
		tiktoken.ENDOFPROMPT: 100276,
	}
	bpe, err := tiktoken.NewCoreBPE(ranks, specialTokens, cl100kPattern)
	if err != nil {
		return nil, fmt.Errorf("compile cl100k_base: %w", err)
	}
	encoding := &tiktoken.Encoding{
		Name:           tiktoken.MODEL_CL100K_BASE,
		PatStr:         cl100kPattern,
		MergeableRanks: ranks,
		SpecialTokens:  specialTokens,
		ExplicitNVocab: 0,
	}
	specialTokenSet := make(map[string]any, len(specialTokens))
	for token := range specialTokens {
		specialTokenSet[token] = struct{}{}
	}
	return tiktoken.NewTiktoken(bpe, encoding, specialTokenSet), nil
}

func loadEmbeddedBPERanks() (map[string]int, error) {
	reader, err := gzip.NewReader(bytes.NewReader(bpeData))
	if err != nil {
		return nil, fmt.Errorf("open embedded cl100k_base: %w", err)
	}
	defer reader.Close()

	bpeRanks := make(map[string]int)
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		encoded, rankText, ok := strings.Cut(line, " ")
		if !ok || strings.Contains(rankText, " ") {
			return nil, fmt.Errorf("invalid embedded cl100k_base line %q", line)
		}

		tokenBytes, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode embedded cl100k_base token: %w", err)
		}

		rank, err := strconv.Atoi(rankText)
		if err != nil {
			return nil, fmt.Errorf("decode embedded cl100k_base rank: %w", err)
		}

		bpeRanks[string(tokenBytes)] = rank
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read embedded cl100k_base: %w", err)
	}

	return bpeRanks, nil
}
