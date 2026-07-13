package rules

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenericCredentialBase64Length(t *testing.T) {
	re := GenericCredential().Regex
	for _, test := range []struct {
		name  string
		value string
		want  bool
	}{
		{"149", "a" + strings.Repeat("/", 148), true},
		{"150", "a" + strings.Repeat("/", 149), true},
		{"151", "a" + strings.Repeat("/", 150), false},
		{"500", "a" + strings.Repeat("/", 499), false},
		{"three padding", "a" + strings.Repeat("/", 146) + "===", true},
		{"four padding", "a" + strings.Repeat("/", 145) + "====", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, re.MatchString("token = "+test.value+"\n"))
		})
	}
}
