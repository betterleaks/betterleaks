package words

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"sync"
)

//go:embed words.txt.gz
var compressedWords []byte

var (
	nltkWords map[string]struct{}
	wordsOnce sync.Once
)

// loadWords decompresses the embedded wordlist and populates the map.
// This is called lazily and is guaranteed to only run exactly once.
func loadWords() {
	nltkWords = make(map[string]struct{})

	gz, err := gzip.NewReader(bytes.NewReader(compressedWords))
	if err != nil {
		panic(err) // Safe to panic here as it implies a corrupted embedded asset
	}
	defer gz.Close()

	scanner := bufio.NewScanner(gz)
	for scanner.Scan() {
		word := scanner.Text()
		if word != "" {
			nltkWords[word] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}
}
