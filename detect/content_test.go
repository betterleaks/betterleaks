package detect

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/internal/contextwindow"
	blregexp "github.com/betterleaks/betterleaks/regexp"
)

func TestScanContentStringAndBytesParity(t *testing.T) {
	raw := "before\nkey = secret\nafter\n"
	for _, content := range []scanContent{stringScanContent(raw), byteScanContent([]byte(raw))} {
		re := blregexp.MustCompile(`secret`)
		require.Equal(t, [][]int{{13, 19}}, content.findAllIndex(re))
		require.Equal(t, "secret", content.trimmedMatch(13, 19))
		require.Equal(t, "key = secret\n", content.sliceString(7, 20))
		require.True(t, content.contains(7, 20, "secret"))
		require.Equal(t, "before\nkey = secret\nafter", content.extractContext([]int{13, 19}, contextwindow.Spec{
			Mode: contextwindow.ModeBox, LinesBefore: 1, LinesAfter: 1,
		}))
	}
}

func TestScanContentMatchSurroundingsParity(t *testing.T) {
	raw := "one\ntwo\npassword = secret\nfour\nfive"
	wantNearby := "one\ntwo\npassword = \n\nfour\nfive"
	for _, content := range []scanContent{stringScanContent(raw), byteScanContent([]byte(raw))} {
		nearby, prefix := content.matchSurroundings(19, 25, 8192, 6)
		require.Equal(t, wantNearby, nearby)
		require.Equal(t, "password = ", prefix)
	}
}

func TestScanContentMatchSurroundingsSeparatesMidLineHalves(t *testing.T) {
	raw := "password = secret; user = root"
	for _, content := range []scanContent{stringScanContent(raw), byteScanContent([]byte(raw))} {
		nearby, prefix := content.matchSurroundings(11, 17, 8192, 6)
		require.Equal(t, "password = \n; user = root", nearby)
		require.Equal(t, "password = ", prefix)
	}
}
