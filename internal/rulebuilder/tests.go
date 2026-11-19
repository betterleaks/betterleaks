package rulebuilder

import "github.com/betterleaks/betterleaks/v2/config"

// Match is a test whose input must produce exactly one finding, secret.
func Match(name, input, secret string) config.RuleTest {
	return config.RuleTest{Name: name, Input: input, Expect: []config.ExpectedFinding{{Secret: secret}}}
}

// NoMatch is a test whose input must produce no findings.
func NoMatch(name, input string) config.RuleTest {
	return config.RuleTest{Name: name, Input: input, Expect: []config.ExpectedFinding{}}
}

// MatchComponent is Match for a skipReport component rule: its standalone
// match, which is never reported on its own, must be exactly secret.
func MatchComponent(name, input, secret string) config.RuleTest {
	test := Match(name, input, secret)
	test.Mode = "match"
	return test
}

// NoMatchComponent is NoMatch for a skipReport component rule: it must not
// match input, even standalone.
func NoMatchComponent(name, input string) config.RuleTest {
	test := NoMatch(name, input)
	test.Mode = "match"
	return test
}
