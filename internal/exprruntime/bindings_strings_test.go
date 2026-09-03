package exprruntime

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitTrim(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		separator string
		want      []string
	}{
		{name: "empty", value: "", separator: ",", want: []string{}},
		{name: "comma separated", value: " repo, read:org, repo, ", separator: ",", want: []string{"repo", "read:org", "repo"}},
		{name: "custom separator", value: "read | write | ", separator: "|", want: []string{"read", "write"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := splitTrim(test.value, test.separator)
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestSplitTrimRejectsEmptySeparator(t *testing.T) {
	_, err := splitTrim("read,write", "")
	require.ErrorContains(t, err, "separator must not be empty")
}
