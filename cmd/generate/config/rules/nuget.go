package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/config"
)

// NugetAPIKey detects nuget.org API keys.
//
// https://github.com/NuGet/NuGetGallery/blob/63b66c98287c61c7e00fe6aefaff86c0d73ba157/src/NuGetGallery.Services/Authentication/ApiKeyV4.cs#L85-L112
func NugetAPIKey() *config.Rule {
	r := config.Rule{
		ID:          "nuget-api-key",
		Confidence:  "high",
		Description: "Detected a NuGet API key, which can push, unlist, or deprecate packages on nuget.org on behalf of its owner.",
		// The 4th, 20th, and last characters hold fixed bits.
		Regex:      utils.GenerateUniqueTokenRegex(`oy2[a-p][a-z2-7]{15}[aq][a-z2-7]{25}[aeimquy4]`, true),
		Keywords:   []string{"oy2"},
		FilterExpr: utils.MinEntropy(3.5),
		// Valid keys get 404 (no such package) or 400 (account policy). Unlist-only keys get 403.
		ValidateExpr: `let r = http.get("https://www.nuget.org/api/v2/verifykey/betterleaks--nonexistent/0.0.0", {
    "X-NuGet-ApiKey": finding["secret"]
  }); (r.status == 404 && (r.body contains "does not exist.")) || r.status == 400 ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "invalid",
    "reason": "Invalid, expired, or missing push scope"
  } : validate.unknown(r)`,
	}

	tps := utils.GenerateSampleSecrets("nuget", "oy2ds22slm75wwyowxgaerhyx5siaqoubbwo3om37cjnby")
	tps = append(tps,
		`dotnet nuget push bin/Release/Contoso.Utils.2.1.0.nupkg --api-key oy2no5jcs4ph6wrgpwgqhz5odtwb5n6u5g4ji7ehk72bdq --source https://api.nuget.org/v3/index.json`,
		`nuget push Contoso.Http.1.0.3.nupkg -k oy2ei7ssfzoxfdagrf5qazloxsohbvuudix6dikmbaj5iu -Source https://api.nuget.org/v3/index.json`,
		`export NUGET_API_KEY=oy2af5ydknylczrpsqwqo2dr5auh662uzfgpjal2ib4n24`,
		`<add key="https://www.nuget.org/api/v2/package" value="oy2nfgigykhohwbp3g4awy2ccqvtwgqellmbj2oiodsgbe" />`,
		`[{"github_token":"ghs_redacted","NUGET_API_KEY":"oy2e4kj6w2zqll7ju72q6425lks6yjiefpyl6zywxdj73y"}]`,
		`$apiKey = 'oy2a5ibb2eklufijqt6qlgftpe3fjzhupg4fyuoyqgsccm'`,
		// any casing
		`--api-key OY2IZT6YMOZVUKMFCARAHVG4ADT4ZGG6HO5I3KQU4WSTCE`,
		`-k oy2P4nnJvgzYtemuPddqdEic5jdZvybvRnghbjmjZr5Q4a`,
	)
	fps := []string{
		// wrong length
		`NUGET_API_KEY=oy2kb2olzfzm4sixjibap4my3j4f4eu7lzosbewy22fam`,
		`NUGET_API_KEY=oy2bseml243y7uqsmokq4jbeyajf5reu5oujojfozfwtyuq`,
		// characters outside the base32 alphabet
		`--api-key oy2myxhfqywo4eirp37qkb4ezzrtip0e3jm2dkfl8efx5a`,
		// fixed bits out of place
		`-k oy2zzbtp73dk4lcfuyuargeoefaqwmbu7pcpy7aznmzeiy`,
		`-k oy2llzlv5xrj7t5tuvjbccwi45j57bae7dhdsq7aignsum`,
		`-k oy2ckwwg6ed53rqvk7vanbrdfbstthdunk5xh3wfwjhctz`,
		// inside a longer token
		`data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkoy2gibrtl6twvyrdkecayyzxmqwqs45ulcn7cw3j7kmgka`,
		// low entropy
		`NUGET_API_KEY=oy2aaaaaaaaaaaaaaaaqaaaaaaaaaaaaaaaaaaaaaaaaaa`,
		// truncated
		`dotnet nuget push *.nupkg --api-key oy2ipw62qgwfkrs3heg... --source nuget.org`,
	}
	return utils.Validate(r, tps, fps)
}

func NugetConfigPassword() *config.Rule {
	r := config.Rule{
		Description: "Identified a password within a Nuget config file, potentially compromising package management access.",
		ID:          "nuget-config-password",
		Confidence:  "high",
		Regex:       `(?i)<add key=\"(?:(?:ClearText)?Password)\"\s*value=\"(.{8,})\"\s*/>`,
		Path:        `(?i)nuget\.config$`,
		Keywords:    []string{"<add key="},
		FilterExpr:  "entropy(finding[\"secret\"]) <= 1.0\n|| matchesAny(finding[\"secret\"], [\n  `33f!!lloppa`,\n  `hal\\+9ooo_da!sY`,\n  `^\\%\\S.*\\%$`\n])",
	}

	tps := map[string]string{
		"nuget.config": `<add key="Password" value="CleartextPassword1" />`,
		"Nuget.config": `<add key="ClearTextPassword" value="CleartextPassword1" />`,
		"Nuget.Config": `<add key="ClearTextPassword" value="TestSourcePassword" />`,
		"Nuget.COnfig": `<add key="ClearTextPassword" value="TestSource-Password" />`,
		"Nuget.CONfig": `<add key="ClearTextPassword" value="TestSource%Password" />`,
		"Nuget.CONFig": `<add key="ClearTextPassword" value="TestSource%Password%" />`,
	}

	fps := map[string]string{
		"some.xml":     `<add key="Password" value="CleartextPassword1" />`,            // wrong filename
		"nuget.config": `<add key="ClearTextPassword" value="XXXXXXXXXXX" />`,          // low entropy
		"Nuget.config": `<add key="ClearTextPassword" value="abc" />`,                  // too short
		"Nuget.Config": `<add key="ClearTextPassword" value="%TestSourcePassword%" />`, // environment variable
		"NUget.Config": `<add key="ClearTextPassword" value="33f!!lloppa" />`,          // known sample
		"NUGet.Config": `<add key="ClearTextPassword" value="hal+9ooo_da!sY" />`,       // known sample
	}
	return utils.ValidateWithPaths(r, tps, fps)
}
