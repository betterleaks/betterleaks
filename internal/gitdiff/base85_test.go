package gitdiff

import (
	"testing"
)

func TestBase85Decode(t *testing.T) {
	tests := map[string]struct {
		Input  string
		Output []byte
		Err    bool
	}{
		"twoBytes": {
			Input:  "%KiWV",
			Output: []byte{0xCA, 0xFE},
		},
		"fourBytes": {
			Input:  "007GV",
			Output: []byte{0x0, 0x0, 0xCA, 0xFE},
		},
		"sixBytes": {
			Input:  "007GV%KiWV",
			Output: []byte{0x0, 0x0, 0xCA, 0xFE, 0xCA, 0xFE},
		},
		"invalidCharacter": {
			Input: "00'GV",
			Err:   true,
		},
		"underpaddedSequence": {
			Input: "007G",
			Err:   true,
		},
		"dataUnderrun": {
			Input:  "007GV",
			Output: make([]byte, 8),
			Err:    true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			dst := make([]byte, len(test.Output))
			err := base85Decode(dst, []byte(test.Input))
			if test.Err {
				if err == nil {
					t.Fatalf("expected error decoding base85 data, but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error decoding base85 data: %v", err)
			}
			for i, b := range test.Output {
				if dst[i] != b {
					t.Errorf("incorrect byte at index %d: expected 0x%X, actual 0x%X", i, b, dst[i])
				}
			}
		})
	}
}
