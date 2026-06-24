package exprenv

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidationBindingAliases(t *testing.T) {
	env, err := New(nil)
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
			oldPrg, err := env.CompileValidation(tc.old)
			require.NoError(t, err)
			newPrg, err := env.CompileValidation(tc.new)
			require.NoError(t, err)

			oldGot, err := env.Eval(oldPrg, nil, nil)
			require.NoError(t, err)
			newGot, err := env.Eval(newPrg, nil, nil)
			require.NoError(t, err)
			require.Equal(t, oldGot, newGot)
		})
	}
}

func TestFilterBindingAliases(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)

	cases := []struct {
		name string
		old  string
		new  string
	}{
		{name: "matchesAny", old: `matchesAny(finding["secret"], ["sec"])`, new: `filter.matchesAny(finding["secret"], ["sec"])`},
		{name: "containsAny", old: `containsAny(finding["secret"], ["secret"])`, new: `filter.containsAny(finding["secret"], ["secret"])`},
		{name: "entropy", old: `entropy(finding["secret"]) > 0`, new: `filter.entropy(finding["secret"]) > 0`},
		{name: "failsTokenEfficiency", old: `failsTokenEfficiency(finding["secret"])`, new: `filter.failsTokenEfficiency(finding["secret"])`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oldPrg, err := env.CompileFilter(tc.old, nil)
			require.NoError(t, err)
			newPrg, err := env.CompileFilter(tc.new, nil)
			require.NoError(t, err)

			finding := map[string]string{"secret": "secret-value"}
			oldGot, err := env.EvalFilter(oldPrg, finding, nil)
			require.NoError(t, err)
			newGot, err := env.EvalFilter(newPrg, finding, nil)
			require.NoError(t, err)
			require.Equal(t, oldGot, newGot)
		})
	}
}
