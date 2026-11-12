package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "sentry-access-token",
	Confidence:  "medium",
	Description: "Found a Sentry.io Access Token (old format), risking unauthorized access to error tracking services and sensitive application data.",
	Regex:       rulebuilder.Assignment([]string{"sentry"}, `(?i)[a-f0-9]{64}`),
	Keywords: []string{
		"sentry",
	},
	FilterExpr: `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `sentryToken = "1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc"`, "1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc"),
	},
})

// format: sntrys_[base64_json]_[base64_secret]
// the json contains the following fields : {"iat": ,"url": ,"region_url": ,"org": }
// Specification: https://github.com/getsentry/rfcs/blob/main/text/0091-ci-upload-tokens.md
// Some test cases from official parser:
// https://github.com/getsentry/sentry-cli/blob/693d62167041846e2da823b7f3b0f21b673b5b1f/src/utils/auth_token/test.rs
// To detect the token, this rule checks for the following base64-encoded json fragments :
// eyJpYXQiO = `{"iat":`,
// LCJyZWdpb25fdXJs = `,"region_url`
// InJlZ2lvbl91cmwi = `"region_url"`
// cmVnaW9uX3VybCI6 = `region_url":`
var _ = rulebuilder.Add(config.Rule{
	ID:          "sentry-org-token",
	Confidence:  "high",
	Description: "Found a Sentry.io Organization Token, risking unauthorized access to error tracking services and sensitive application data.",
	Regex:       `\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}(?:[^a-zA-Z0-9+/]|\z)`,
	Keywords:    []string{"sntrys_eyjpyxqio"},
	FilterExpr:  `entropy(finding["secret"]) < 4.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `sentryToken = "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"`, `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"`),
		rulebuilder.Match("sentry assignment 2", `sentryToken = "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"`, `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"`),
		rulebuilder.Match("true positive 1", " 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", "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"),
		rulebuilder.Match("bare secret", "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", "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"),
		rulebuilder.Match("true positive 2", "<token>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</token>", "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<"),
		rulebuilder.Match("true positive 3", "https://example.com?token=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&other=stuff", "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&"),
		rulebuilder.NoMatch("does not contain encoded json", "sntrys_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyKl17ltLSvQmntzYlkmifsd2X28mLGpj0sdzvhNhjpXm_kI0TwXU3Pqj71n5gwFoigtDswxBrlgaWd1iKZUz5g1P"),
		rulebuilder.NoMatch("too short", "sntrys_eyJpYXQiOjAwOCwidXJsIjoiaHR0cHM6Ly90RHhwUTRGV1ljIiwicmVnaW9uX3VybCI6Imh0dHBzOi8vYk1xMEt0NWI5d3NfcGdzeFVtT2UiLCJvcmciOiJXM3pmNyJ9_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klK"),
		rulebuilder.NoMatch("too long", "sntrys_eyJpYXQiOjAwOCwidXJsIjoiaHR0cHM6Ly90RHhwUTRGV1ljIiwicmVnaW9uX3VybCI6Imh0dHBzOi8vYk1xMEt0NWI5d3NfcGdzeFVtT2UiLCJvcmciOiJXM3pmNyJ9_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "sentry-user-token",
	Confidence:  "high",
	Description: "Found a Sentry.io User Token, risking unauthorized access to error tracking services and sensitive application data.",
	Regex:       rulebuilder.Token(`sntryu_[a-f0-9]{64}`),
	Keywords:    []string{"sntryu_"},
	FilterExpr:  `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `sentryToken = "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"`, "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"),
		rulebuilder.NoMatch("too short", "sntryu_1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3ed"),
		rulebuilder.NoMatch("too long", "sntryu_1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edca"),
		rulebuilder.NoMatch("low entropy", "sntryu_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
	},
})
