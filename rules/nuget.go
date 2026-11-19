package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// NugetAPIKey detects nuget.org API keys.
//
// https://github.com/NuGet/NuGetGallery/blob/63b66c98287c61c7e00fe6aefaff86c0d73ba157/src/NuGetGallery.Services/Authentication/ApiKeyV4.cs#L85-L112
var _ = rulebuilder.Add(config.Rule{
	ID:          "nuget-api-key",
	Confidence:  "high",
	Description: "Detected a NuGet API key, which can push, unlist, or deprecate packages on nuget.org on behalf of its owner.",
	// The 4th, 20th, and last characters hold fixed bits.
	Regex:      rulebuilder.Token(`(?i)oy2[a-p][a-z2-7]{15}[aq][a-z2-7]{25}[aeimquy4]`),
	Keywords:   []string{"oy2"},
	FilterExpr: rulebuilder.MinEntropy(3.5),
	// Valid keys get 404 (no such package) or 400 (account policy). Unlist-only keys get 403.
	ValidateExpr: `let r = http.get("https://www.nuget.org/api/v2/verifykey/betterleaks--nonexistent/0.0.0", {
    "X-NuGet-ApiKey": finding["secret"]
  }); (r.status == 404 && (r.body contains "does not exist.")) || r.status == 400 ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "invalid",
    "reason": "Invalid, expired, or missing push scope"
  } : validate.unknown(r)`,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `nugetToken = "oy2ds22slm75wwyowxgaerhyx5siaqoubbwo3om37cjnby"`, "oy2ds22slm75wwyowxgaerhyx5siaqoubbwo3om37cjnby"),
		rulebuilder.Match("true positive 1", "dotnet nuget push bin/Release/Contoso.Utils.2.1.0.nupkg --api-key oy2no5jcs4ph6wrgpwgqhz5odtwb5n6u5g4ji7ehk72bdq --source https://api.nuget.org/v3/index.json", "oy2no5jcs4ph6wrgpwgqhz5odtwb5n6u5g4ji7ehk72bdq"),
		rulebuilder.Match("true positive 2", "nuget push Contoso.Http.1.0.3.nupkg -k oy2ei7ssfzoxfdagrf5qazloxsohbvuudix6dikmbaj5iu -Source https://api.nuget.org/v3/index.json", "oy2ei7ssfzoxfdagrf5qazloxsohbvuudix6dikmbaj5iu"),
		rulebuilder.Match("true positive 3", "export NUGET_API_KEY=oy2af5ydknylczrpsqwqo2dr5auh662uzfgpjal2ib4n24", "oy2af5ydknylczrpsqwqo2dr5auh662uzfgpjal2ib4n24"),
		rulebuilder.Match("true positive 4", `<add key="https://www.nuget.org/api/v2/package" value="oy2nfgigykhohwbp3g4awy2ccqvtwgqellmbj2oiodsgbe" />`, "oy2nfgigykhohwbp3g4awy2ccqvtwgqellmbj2oiodsgbe"),
		rulebuilder.Match("true positive 5", `[{"github_token":"ghs_redacted","NUGET_API_KEY":"oy2e4kj6w2zqll7ju72q6425lks6yjiefpyl6zywxdj73y"}]`, "oy2e4kj6w2zqll7ju72q6425lks6yjiefpyl6zywxdj73y"),
		rulebuilder.Match("true positive 6", "$apiKey = 'oy2a5ibb2eklufijqt6qlgftpe3fjzhupg4fyuoyqgsccm'", "oy2a5ibb2eklufijqt6qlgftpe3fjzhupg4fyuoyqgsccm"),
		rulebuilder.Match("true positive 7", "--api-key OY2IZT6YMOZVUKMFCARAHVG4ADT4ZGG6HO5I3KQU4WSTCE", "OY2IZT6YMOZVUKMFCARAHVG4ADT4ZGG6HO5I3KQU4WSTCE"),
		rulebuilder.Match("true positive 8", "-k oy2P4nnJvgzYtemuPddqdEic5jdZvybvRnghbjmjZr5Q4a", "oy2P4nnJvgzYtemuPddqdEic5jdZvybvRnghbjmjZr5Q4a"),
		rulebuilder.NoMatch("wrong length", "NUGET_API_KEY=oy2kb2olzfzm4sixjibap4my3j4f4eu7lzosbewy22fam"),
		rulebuilder.NoMatch("false positive 1", "NUGET_API_KEY=oy2bseml243y7uqsmokq4jbeyajf5reu5oujojfozfwtyuq"),
		rulebuilder.NoMatch("characters outside the base32 alphabet", "--api-key oy2myxhfqywo4eirp37qkb4ezzrtip0e3jm2dkfl8efx5a"),
		rulebuilder.NoMatch("fixed bits out of place", "-k oy2zzbtp73dk4lcfuyuargeoefaqwmbu7pcpy7aznmzeiy"),
		rulebuilder.NoMatch("false positive 2", "-k oy2llzlv5xrj7t5tuvjbccwi45j57bae7dhdsq7aignsum"),
		rulebuilder.NoMatch("false positive 3", "-k oy2ckwwg6ed53rqvk7vanbrdfbstthdunk5xh3wfwjhctz"),
		rulebuilder.NoMatch("inside a longer token", "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkoy2gibrtl6twvyrdkecayyzxmqwqs45ulcn7cw3j7kmgka"),
		rulebuilder.NoMatch("low entropy", "NUGET_API_KEY=oy2aaaaaaaaaaaaaaaaqaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		rulebuilder.NoMatch("truncated", "dotnet nuget push *.nupkg --api-key oy2ipw62qgwfkrs3heg... --source nuget.org"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	Description: "Identified a password within a Nuget config file, potentially compromising package management access.",
	ID:          "nuget-config-password",
	Confidence:  "high",
	Regex:       `(?i)<add key=\"(?:(?:ClearText)?Password)\"\s*value=\"(.{8,})\"\s*/>`,
	Path:        `(?i)nuget\.config$`,
	Keywords:    []string{"<add key="},
	FilterExpr:  "entropy(finding[\"secret\"]) <= 1.0\n|| matchesAny(finding[\"secret\"], [\n  `33f!!lloppa`,\n  `hal\\+9ooo_da!sY`,\n  `^\\%\\S.*\\%$`\n])",
	Tests: []config.RuleTest{
		{
			Name:       "true positive 1",
			Input:      `<add key="ClearTextPassword" value="TestSource%Password%" />`,
			Attributes: map[string]string{"path": "Nuget.CONFig"},
			Expect: []config.ExpectedFinding{
				{Secret: "TestSource%Password%"},
			},
		},
		{
			Name:       "true positive 2",
			Input:      `<add key="ClearTextPassword" value="TestSource%Password" />`,
			Attributes: map[string]string{"path": "Nuget.CONfig"},
			Expect: []config.ExpectedFinding{
				{Secret: "TestSource%Password"},
			},
		},
		{
			Name:       "true positive 3",
			Input:      `<add key="ClearTextPassword" value="TestSource-Password" />`,
			Attributes: map[string]string{"path": "Nuget.COnfig"},
			Expect: []config.ExpectedFinding{
				{Secret: "TestSource-Password"},
			},
		},
		{
			Name:       "true positive 4",
			Input:      `<add key="ClearTextPassword" value="TestSourcePassword" />`,
			Attributes: map[string]string{"path": "Nuget.Config"},
			Expect: []config.ExpectedFinding{
				{Secret: "TestSourcePassword"},
			},
		},
		{
			Name:       "true positive 5",
			Input:      `<add key="ClearTextPassword" value="CleartextPassword1" />`,
			Attributes: map[string]string{"path": "Nuget.config"},
			Expect: []config.ExpectedFinding{
				{Secret: "CleartextPassword1"},
			},
		},
		{
			Name:       "wrong filename",
			Input:      `<add key="Password" value="CleartextPassword1" />`,
			Attributes: map[string]string{"path": "nuget.config"},
			Expect: []config.ExpectedFinding{
				{Secret: "CleartextPassword1"},
			},
		},
		{
			Name:       "known sample",
			Input:      `<add key="ClearTextPassword" value="hal+9ooo_da!sY" />`,
			Attributes: map[string]string{"path": "NUGet.Config"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "known sample 2",
			Input:      `<add key="ClearTextPassword" value="33f!!lloppa" />`,
			Attributes: map[string]string{"path": "NUget.Config"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "environment variable",
			Input:      `<add key="ClearTextPassword" value="%TestSourcePassword%" />`,
			Attributes: map[string]string{"path": "Nuget.Config"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "too short",
			Input:      `<add key="ClearTextPassword" value="abc" />`,
			Attributes: map[string]string{"path": "Nuget.config"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "low entropy",
			Input:      `<add key="ClearTextPassword" value="XXXXXXXXXXX" />`,
			Attributes: map[string]string{"path": "nuget.config"},
			Expect:     []config.ExpectedFinding{},
		},
		{
			Name:       "wrong filename 2",
			Input:      `<add key="Password" value="CleartextPassword1" />`,
			Attributes: map[string]string{"path": "some.xml"},
			Expect:     []config.ExpectedFinding{},
		},
	},
})
