package detect

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/base64"
	"strconv"
	"strings"
)

//go:embed assets/cl100k_base.tiktoken.gz
var compressedBPEData []byte

// MyCustomLoader implements the tiktoken.BpeLoader interface
type TiktokenLoader struct{}

// LoadTiktokenBpe decompresses the embedded file and parses it into the expected map
func (l *TiktokenLoader) LoadTiktokenBpe(file string) (map[string]int, error) {
	gz, err := gzip.NewReader(bytes.NewReader(compressedBPEData))
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	bpeRanks := make(map[string]int)
	scanner := bufio.NewScanner(gz)

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
