package celenv

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"
)

func TestValidationBindingAliases(t *testing.T) {
	env, err := NewEnvironment(nil)
	require.NoError(t, err)

	cases := []struct {
		name string
		old  string
		new  string
	}{
		{
			name: "hmac sha256",
			old:  `hex.encode(crypto.hmac_sha256(bytes("key"), bytes("hello")))`,
			new:  `hex.encode(crypto.hmacSha256(bytes("key"), bytes("hello")))`,
		},
		{
			name: "unknown",
			old:  `unknown({"status": 429}).reason`,
			new:  `validate.unknown({"status": 429}).reason`,
		},
		{
			name: "obfuscate",
			old:  `size(obfuscate("short-secret"))`,
			new:  `size(strings.obfuscate("short-secret"))`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oldPrg, err := env.Compile(tc.old)
			require.NoError(t, err)
			newPrg, err := env.Compile(tc.new)
			require.NoError(t, err)

			oldGot, err := env.Eval(oldPrg, nil, nil)
			require.NoError(t, err)
			newGot, err := env.Eval(newPrg, nil, nil)
			require.NoError(t, err)
			require.Equal(t, oldGot.Value(), newGot.Value())
		})
	}
}

func TestFilterBindingAliases(t *testing.T) {
	env, err := NewFilterEnv(nil)
	require.NoError(t, err)

	cases := []struct {
		name string
		old  string
		new  string
	}{
		{name: "matchesAny", old: `matchesAny(finding["secret"], ["sec"])`, new: `filter.matchesAny(finding["secret"], ["sec"])`},
		{name: "containsAny", old: `containsAny(finding["secret"], ["secret"])`, new: `filter.containsAny(finding["secret"], ["secret"])`},
		{name: "entropy", old: `entropy(finding["secret"])`, new: `filter.entropy(finding["secret"])`},
		{name: "failsTokenEfficiency", old: `failsTokenEfficiency(finding["secret"])`, new: `filter.failsTokenEfficiency(finding["secret"])`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oldPrg, err := env.Compile(tc.old)
			require.NoError(t, err)
			newPrg, err := env.Compile(tc.new)
			require.NoError(t, err)

			finding := map[string]string{"secret": "secret-value"}
			oldGot, err := evalFilterValue(oldPrg, finding, nil)
			require.NoError(t, err)
			newGot, err := evalFilterValue(newPrg, finding, nil)
			require.NoError(t, err)
			require.Equal(t, oldGot, newGot)
		})
	}
}

func evalFilterValue(prg cel.Program, finding, attributes map[string]string) (any, error) {
	if finding == nil {
		finding = emptyStringMap
	}
	if attributes == nil {
		attributes = emptyStringMap
	}
	val, _, err := prg.Eval(map[string]any{
		"finding":    finding,
		"attributes": attributes,
	})
	if err != nil {
		return nil, err
	}
	return val.Value(), nil
}
