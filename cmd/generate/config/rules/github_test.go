package rules

import (
	"strconv"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/regexp"

	"github.com/stretchr/testify/require"
)

func TestGitHubRefreshTokenBoundaries(t *testing.T) {
	rule := GitHubRefresh()
	pattern := regexp.MustCompile(rule.Regex)
	token := "ghr_" + strings.Repeat("A", 76)

	for _, tc := range []struct {
		name  string
		input string
	}{
		{name: "delimiter", input: token + ","},
		{name: "end of input", input: token},
	} {
		t.Run(tc.name, func(t *testing.T) {
			match := pattern.FindStringSubmatch(tc.input)
			require.NotNil(t, match)
			require.Equal(t, token, match[rule.ValueGroup])
		})
	}

	for _, length := range []int{36, 75, 77} {
		t.Run("reject length "+strconv.Itoa(length), func(t *testing.T) {
			input := "ghr_" + strings.Repeat("A", length)
			require.False(t, pattern.MatchString(input))
		})
	}
}
