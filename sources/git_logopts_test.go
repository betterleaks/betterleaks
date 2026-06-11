package sources

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSplitGitLogOpts(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		expect  []string
		errText string
	}{
		{
			name:   "quoted value remains one argument",
			input:  "--all --since='90 days ago'",
			expect: []string{"--all", "--since=90 days ago"},
		},
		{
			name:   "double quoted value remains one argument",
			input:  "--author=\"Jane Doe\" --all",
			expect: []string{"--author=Jane Doe", "--all"},
		},
		{
			name:   "escaped space works",
			input:  "--grep=bug\\ fix --all",
			expect: []string{"--grep=bug fix", "--all"},
		},
		{
			name:    "unterminated quote returns error",
			input:   "--since='90 days ago",
			errText: "unterminated quote",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := splitGitLogOpts(tt.input)
			if tt.errText != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.errText)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expect, actual)
		})
	}
}

