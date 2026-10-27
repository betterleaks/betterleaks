//go:build !unix

package gitfs

import "os"

const NonBlocking = 0

func mapFile(*os.File, int) ([]byte, error) { return nil, os.ErrInvalid }
func unmapFile([]byte) error                { return nil }
