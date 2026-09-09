package gitdiff

import (
	"encoding/binary"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestParseBinaryMarker(t *testing.T) {
	tests := map[string]struct {
		Input    string
		IsBinary bool
		HasData  bool
		Err      bool
	}{
		"binaryPatch": {
			Input:    "GIT binary patch\n",
			IsBinary: true,
			HasData:  true,
		},
		"binaryFileNoPatch": {
			Input:    "Binary files differ\n",
			IsBinary: true,
			HasData:  false,
		},
		"textFile": {
			Input:    "@@ -10,14 +22,31 @@\n",
			IsBinary: false,
			HasData:  false,
		},
		"binaryPatchCreated": {
			Input:    "Binary files /dev/null and b/path/to/file.ext differ\n",
			IsBinary: true,
			HasData:  false,
		},
		"binaryPatchModified": {
			Input:    "Binary files a/path/to/file.ext and b/path/to/file.ext differ\n",
			IsBinary: true,
			HasData:  false,
		},
		"binaryPatchModifiedQuoted": {
			Input:    "Binary files \"a/path/to/file.ext\" and \"b/path/to/file.ext\" differ\n",
			IsBinary: true,
			HasData:  false,
		},
		"binaryPatchDeleted": {
			Input:    "Binary files a/path/to/file.ext and /dev/null differ\n",
			IsBinary: true,
			HasData:  false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newTestParser(test.Input, true)

			isBinary, hasData, err := p.ParseBinaryMarker()
			if test.Err {
				if err == nil || err == io.EOF {
					t.Fatalf("expected error parsing binary marker, but got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error parsing binary marker: %v", err)
			}
			if test.IsBinary != isBinary {
				t.Errorf("incorrect isBinary value: expected %t, actual %t", test.IsBinary, isBinary)
			}
			if test.HasData != hasData {
				t.Errorf("incorrect hasData value: expected %t, actual %t", test.HasData, hasData)
			}
		})
	}
}

func TestParseBinaryFragmentHeader(t *testing.T) {
	tests := map[string]struct {
		Input  string
		Output *BinaryFragment
		Err    bool
	}{
		"delta": {
			Input: "delta 1234\n",
			Output: &BinaryFragment{
				Method: BinaryPatchDelta,
				Size:   1234,
			},
		},
		"literal": {
			Input: "literal 1234\n",
			Output: &BinaryFragment{
				Method: BinaryPatchLiteral,
				Size:   1234,
			},
		},
		"unknownMethod": {
			Input:  "compressed 1234\n",
			Output: nil,
		},
		"notAHeader": {
			Input:  "Binary files differ\n",
			Output: nil,
		},
		"invalidSize": {
			Input: "delta 123abc\n",
			Err:   true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newTestParser(test.Input, true)

			frag, err := p.ParseBinaryFragmentHeader()
			if test.Err {
				if err == nil || err == io.EOF {
					t.Fatalf("expected error parsing binary header, but got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error parsing binary header: %v", err)
			}
			if !reflect.DeepEqual(test.Output, frag) {
				t.Errorf("incorrect binary fragment\nexpected: %+v\n  actual: %+v", test.Output, frag)
			}
		})
	}
}

func TestParseBinaryChunk(t *testing.T) {
	tests := map[string]struct {
		Input    string
		Fragment BinaryFragment
		Output   []byte
		Err      string
	}{
		"singleline": {
			Input: "TcmZQzU|?i`U?w2V48*Je09XJG\n\n",
			Fragment: BinaryFragment{
				Size: 20,
			},
			Output: fib(5, binary.BigEndian),
		},
		"multiline": {
			Input: "zcmZQzU|?i`U?w2V48*KJ%mKu_Kr9NxN<eH5#F0Qe0f=7$l~*z_FeL$%-)3N7vt?l5\n" +
				"zl3-vE2xVZ9%4J~CI>f->s?WfX|B-=Vs{#X~svra7Ekg#T|4s}nH;WnAZ)|1Y*`&cB\n" +
				"s(sh?X(Uz6L^!Ou&aF*u`J!eibJifSrv0z>$Q%Hd(^HIJ<Y?5`S0gT5UE&u=k\n\n",
			Fragment: BinaryFragment{
				Size: 160,
			},
			Output: fib(40, binary.BigEndian),
		},
		"shortLine": {
			Input: "A00\n\n",
			Err:   "corrupt data line",
		},
		"underpaddedLine": {
			Input: "H00000000\n\n",
			Err:   "corrupt data line",
		},
		"invalidLengthByte": {
			Input: "!00000\n\n",
			Err:   "invalid length byte",
		},
		"miscountedLine": {
			Input: "H00000\n\n",
			Err:   "incorrect byte count",
		},
		"invalidEncoding": {
			Input: "TcmZQzU|?i'U?w2V48*Je09XJG\n",
			Err:   "invalid base85 byte",
		},
		"noTrailingEmptyLine": {
			Input: "TcmZQzU|?i`U?w2V48*Je09XJG\n",
			Err:   "unexpected EOF",
		},
		"invalidCompression": {
			Input: "F007GV%KiWV\n\n",
			Err:   "zlib",
		},
		"incorrectSize": {
			Input: "TcmZQzU|?i`U?w2V48*Je09XJG\n\n",
			Fragment: BinaryFragment{
				Size: 16,
			},
			Err: "16 byte fragment inflated to 20",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newTestParser(test.Input, true)

			frag := test.Fragment
			err := p.ParseBinaryChunk(&frag)
			if test.Err != "" {
				if err == nil || !strings.Contains(err.Error(), test.Err) {
					t.Fatalf("expected error containing %q parsing binary chunk, but got %v", test.Err, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error parsing binary chunk: %v", err)
			}
			if !reflect.DeepEqual(test.Output, frag.Data) {
				t.Errorf("incorrect binary chunk\nexpected: %+v\n  actual: %+v", test.Output, frag.Data)
			}
		})
	}
}

func TestParseBinaryFragments(t *testing.T) {
	tests := map[string]struct {
		Input string
		File  File

		Binary          bool
		Fragment        *BinaryFragment
		ReverseFragment *BinaryFragment
		Err             bool
	}{
		"dataWithReverse": {
			Input: `GIT binary patch
literal 40
gcmZQzU|?i` + "`" + `U?w2V48*KJ%mKu_Kr9NxN<eH500b)lkN^Mx

literal 0
HcmV?d00001

`,
			Binary: true,
			Fragment: &BinaryFragment{
				Method: BinaryPatchLiteral,
				Size:   40,
				Data:   fib(10, binary.BigEndian),
			},
			ReverseFragment: &BinaryFragment{
				Method: BinaryPatchLiteral,
				Size:   0,
				Data:   []byte{},
			},
		},
		"dataWithoutReverse": {
			Input: `GIT binary patch
literal 40
gcmZQzU|?i` + "`" + `U?w2V48*KJ%mKu_Kr9NxN<eH500b)lkN^Mx

`,
			Binary: true,
			Fragment: &BinaryFragment{
				Method: BinaryPatchLiteral,
				Size:   40,
				Data:   fib(10, binary.BigEndian),
			},
		},
		"noData": {
			Input:  "Binary files differ\n",
			Binary: true,
		},
		"text": {
			Input: `@@ -1 +1 @@
-old line
+new line
`,
			Binary: false,
		},
		"missingData": {
			Input: "GIT binary patch\n",
			Err:   true,
		},
		"invalidData": {
			Input: `GIT binary patch
literal 20
TcmZQzU|?i'U?w2V48*Je09XJG

`,
			Err: true,
		},
		"invalidReverseData": {
			Input: `GIT binary patch
literal 20
TcmZQzU|?i` + "`" + `U?w2V48*Je09XJG

literal 0
zcmV?d00001

`,
			Err: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newTestParser(test.Input, true)

			file := test.File
			_, err := p.ParseBinaryFragments(&file)
			if test.Err {
				if err == nil || err == io.EOF {
					t.Fatalf("expected error parsing binary fragments, but got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error parsing binary fragments: %v", err)
			}
			if test.Binary != file.IsBinary {
				t.Errorf("incorrect binary state: expected %t, actual %t", test.Binary, file.IsBinary)
			}
			if !reflect.DeepEqual(test.Fragment, file.BinaryFragment) {
				t.Errorf("incorrect binary fragment\nexpected: %+v\n  actual: %+v", test.Fragment, file.BinaryFragment)
			}
			if !reflect.DeepEqual(test.ReverseFragment, file.ReverseBinaryFragment) {
				t.Errorf("incorrect reverse binary fragment\nexpected: %+v\n  actual: %+v", test.ReverseFragment, file.ReverseBinaryFragment)
			}
		})
	}
}

func fib(n int, ord binary.ByteOrder) []byte {
	buf := make([]byte, 4*n)
	for i := 0; i < len(buf); i += 4 {
		if i < 8 {
			ord.PutUint32(buf[i:], 1)
		} else {
			ord.PutUint32(buf[i:], ord.Uint32(buf[i-4:])+ord.Uint32(buf[i-8:]))
		}
	}
	return buf
}
