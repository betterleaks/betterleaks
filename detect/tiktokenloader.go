package detect

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/base64"
	"io"
	"strconv"
	"strings"
)

//go:embed assets/cl100k_base.tiktoken.gz
var bpeData []byte

// TikTokenLoader implements the tiktoken.BpeLoader interface
type TiktokenLoader struct{}

// LoadTiktokenBpe parses the embedded BPE file into the expected map.
func (l *TiktokenLoader) LoadTiktokenBpe(file string) (map[string]int, error) {
	reader, err := gzip.NewReader(bytes.NewReader(bpeData))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	bpeRanks := make(map[string]int)
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		parts := strings.Split(line, " ")
		if len(parts) != 2 {
			continue
		}

		tokenBytes, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return nil, err
		}

		rank, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, err
		}

		bpeRanks[string(tokenBytes)] = rank
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return bpeRanks, nil
}
