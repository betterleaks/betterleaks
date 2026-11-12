package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	Description: "Discovered a Sidekiq Secret, which could lead to compromised background job processing and application data breaches.",
	ID:          "sidekiq-secret",
	Confidence:  "high",
	Regex: rulebuilder.Assignment(
		[]string{"BUNDLE_ENTERPRISE__CONTRIBSYS__COM", "BUNDLE_GEMS__CONTRIBSYS__COM"},
		`(?i)[a-f0-9]{8}:[a-f0-9]{8}`,
	),
	Keywords: []string{"bundle_enterprise__contribsys__com", "bundle_gems__contribsys__com"},
	Tests: []config.RuleTest{
		rulebuilder.Match("BUNDLE_ENTERPRISE__CONTRIBSYS__COM assignment", `BUNDLE_ENTERPRISE__CONTRIBSYS__COMToken = "1f7b169c:846f218a"`, "1f7b169c:846f218a"),
		rulebuilder.Match("BUNDLE_GEMS__CONTRIBSYS__COM assignment", `BUNDLE_GEMS__CONTRIBSYS__COMToken = "1f7b169c:846f218a"`, "1f7b169c:846f218a"),
		rulebuilder.Match("true positive 1", "BUNDLE_ENTERPRISE__CONTRIBSYS__COM: cafebabe:deadbeef", "cafebabe:deadbeef"),
		rulebuilder.Match("true positive 2", "export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef", "cafebabe:deadbeef"),
		rulebuilder.Match("true positive 3", "export BUNDLE_ENTERPRISE__CONTRIBSYS__COM = cafebabe:deadbeef", "cafebabe:deadbeef"),
		rulebuilder.Match("true positive 4", `BUNDLE_GEMS__CONTRIBSYS__COM: "cafebabe:deadbeef"`, "cafebabe:deadbeef"),
		rulebuilder.Match("true positive 5", `export BUNDLE_GEMS__CONTRIBSYS__COM="cafebabe:deadbeef"`, "cafebabe:deadbeef"),
		rulebuilder.Match("true positive 6", `export BUNDLE_GEMS__CONTRIBSYS__COM = "cafebabe:deadbeef"`, "cafebabe:deadbeef"),
		rulebuilder.Match("true positive 7", "export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef;", "cafebabe:deadbeef"),
		rulebuilder.Match("true positive 8", "export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef && echo 'hello world'", "cafebabe:deadbeef"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	Description: "Uncovered a Sidekiq Sensitive URL, potentially exposing internal job queues and sensitive operation details.",
	ID:          "sidekiq-sensitive-url",
	Confidence:  "high",
	Regex:       `(?i)\bhttps?://([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\/|\#|\?|:]|$)`,
	Keywords:    []string{"gems.contribsys.com", "enterprise.contribsys.com"},
	Tests: []config.RuleTest{
		rulebuilder.Match("true positive 1", "https://cafebabe:deadbeef@gems.contribsys.com/", "cafebabe:deadbeef"),
		rulebuilder.Match("true positive 2", "https://cafebabe:deadbeef@gems.contribsys.com", "cafebabe:deadbeef"),
		rulebuilder.Match("true positive 3", "https://cafeb4b3:d3adb33f@enterprise.contribsys.com/", "cafeb4b3:d3adb33f"),
		rulebuilder.Match("true positive 4", "https://cafeb4b3:d3adb33f@enterprise.contribsys.com", "cafeb4b3:d3adb33f"),
		rulebuilder.Match("true positive 5", "http://cafebabe:deadbeef@gems.contribsys.com/", "cafebabe:deadbeef"),
		rulebuilder.Match("true positive 6", "http://cafebabe:deadbeef@gems.contribsys.com", "cafebabe:deadbeef"),
		rulebuilder.Match("true positive 7", "http://cafeb4b3:d3adb33f@enterprise.contribsys.com/", "cafeb4b3:d3adb33f"),
		rulebuilder.Match("true positive 8", "http://cafeb4b3:d3adb33f@enterprise.contribsys.com", "cafeb4b3:d3adb33f"),
		rulebuilder.Match("true positive 9", "http://cafeb4b3:d3adb33f@enterprise.contribsys.com#heading1", "cafeb4b3:d3adb33f"),
		rulebuilder.Match("true positive 10", "http://cafeb4b3:d3adb33f@enterprise.contribsys.com?param1=true&param2=false", "cafeb4b3:d3adb33f"),
		rulebuilder.Match("true positive 11", "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80", "cafeb4b3:d3adb33f"),
		rulebuilder.Match("true positive 12", "http://cafeb4b3:d3adb33f@enterprise.contribsys.com:80/path?param1=true&param2=false#heading1", "cafeb4b3:d3adb33f"),
	},
})
