//go:build !unix

package sources

import "os"

// rawFile wraps os.File where the descriptor-level fast path is unavailable.
type rawFile struct {
	*os.File
}

func openFile(path string) (*rawFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return &rawFile{File: f}, nil
}

func (f *rawFile) Size() (int64, error) {
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}
