package codec

import (
	"encoding/base64"
	"math/rand/v2"
	"testing"
)

func TestBase64ScratchParity(t *testing.T) {
	// Compare against the previous allocating implementation, including the
	// transition from stack to heap storage and partially decoded failures.
	reference := func(value string) string {
		if !hasByte(value, likelyBase64Chars) {
			return ""
		}
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
			decoded, err := encoding.DecodeString(value)
			if err == nil && isPrintableASCII(decoded) {
				return string(decoded)
			}
		}
		return ""
	}
	random := rand.New(rand.NewPCG(1, 2))
	for _, length := range []int{0, 1, 2, 3, 16, 255, 256, 257, 1024} {
		for range 100 {
			data := make([]byte, length)
			for i := range data {
				data[i] = byte(32 + random.IntN(95))
			}
			for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
				value := encoding.EncodeToString(data)
				for _, input := range []string{value, value + "-", value + "=", string(data)} {
					if got, want := decodeBase64(input), reference(input); got != want {
						t.Fatalf("length %d: got %q, want %q", length, got, want)
					}
				}
			}
		}
	}
}
