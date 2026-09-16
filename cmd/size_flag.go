package cmd

import (
	"fmt"
	"math"

	"github.com/alecthomas/kong"
	"github.com/dustin/go-humanize"
)

// sizeFlag accepts human-readable byte sizes (e.g. 1GiB, 250MB) on the
// command line while behaving like an int64 everywhere else.
type sizeFlag int64

func (s *sizeFlag) Decode(ctx *kong.DecodeContext) error {
	token, err := ctx.Scan.PopValue("size")
	if err != nil {
		return err
	}
	value, ok := token.Value.(string)
	if !ok {
		return fmt.Errorf("expected size string, got %T", token.Value)
	}
	n, err := parseSize(value)
	if err != nil {
		return err
	}
	*s = sizeFlag(n)
	return nil
}

// parseSize converts a human-readable size string to bytes. Empty string returns 0.
func parseSize(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	n, err := humanize.ParseBytes(s)
	if err != nil {
		return 0, err
	}
	if n > math.MaxInt64 {
		return 0, fmt.Errorf("size %q overflows int64 (max %d bytes)", s, int64(math.MaxInt64))
	}
	return int64(n), nil
}
