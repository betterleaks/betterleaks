package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

const jfrogHost = "\nARTIFACTORY_URL=https://mycompany.jfrog.io"

var _ = rulebuilder.Add(config.Rule{
	ID:          "artifactory-api-key",
	Confidence:  "high",
	Description: "Detected an Artifactory api key, posing a risk unauthorized access to the central repository.",
	Regex:       `\bAKCp[A-Za-z0-9]{68,70}\b`,
	Keywords:    []string{"akcp"},
	Components: []config.Component{
		{RuleID: "artifactory-jfrog-url"},
	},
	ValidateExpr: `let r = http.get("https://" + (components["artifactory-jfrog-url"]?.secret ?? "") + "/artifactory/api/security/apiKey", {
  "X-JFrog-Art-Api": finding["secret"],
  "Accept": "application/json"
});
let isJSON = lower(trim(split(r.headers["content-type"] ?? "", ";")[0])) == "application/json";
let body = type(r.json) == "map" ? r.json : {};
r.status == 200 && isJSON && (body?.apiKey ?? "") == finding["secret"] ? {
  "result": "valid"
} : r.status == 401 && isJSON && type(body?.errors) == "array" && any(body.errors, { type(#) == "map" && (#.status ?? 0) == 401 }) ? {
  "result": "invalid",
  "reason": "Invalid API key"
} : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5`,
	Tests: []config.RuleTest{
		{
			Name:  "key with host",
			Input: "artifactoryApiKey := \"AKCp5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lca8hqn\"" + jfrogHost,
			Expect: []config.ExpectedFinding{
				{Secret: "AKCp5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lca8hqn", ComponentSets: []map[string]string{{"artifactory-jfrog-url": "mycompany.jfrog.io"}}},
			},
		},
		rulebuilder.NoMatch("key without host", `artifactoryApiKey := "AKCp5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lca8hqn"`),
		rulebuilder.NoMatch("low entropy", "lowEntropy := AKCpXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"+jfrogHost),
		rulebuilder.NoMatch("wrong prefix case", `wrongStart := "AkCp5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lca8hqn"`+jfrogHost),
		rulebuilder.NoMatch("too short", `wrongLength := "AKCp5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7"`+jfrogHost),
		rulebuilder.NoMatch("inside a longer blob", "partOfAlongUnrelatedBlob gYnkgAKCp5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lca8hqnVyZSB2"+jfrogHost),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "artifactory-reference-token",
	Confidence:  "high",
	Description: "Detected an Artifactory reference token, posing a risk of impersonation and unauthorized access to the central repository.",
	Regex:       `\bcmVmd[A-Za-z0-9]{59}\b`,
	Keywords:    []string{"cmvmd"},
	Components: []config.Component{
		{RuleID: "artifactory-jfrog-url"},
	},
	ValidateExpr: `let secret = finding["secret"];
let url = "https://" + (components["artifactory-jfrog-url"]?.secret ?? "") + "/artifactory/api/system/ping";
let r = http.get(url, {"Authorization": "Bearer " + secret, "Accept": "text/plain"});
let contentType = lower(trim(split(r.headers["content-type"] ?? "", ";")[0]));
let body = type(r.json) == "map" ? r.json : {};
r.status == 401 && contentType == "application/json" && type(body?.errors) == "array" && any(body.errors, { type(#) == "map" && (#.status ?? 0) == 401 }) ? {
  "result": "invalid",
  "reason": "Invalid reference token"
} : r.status == 200 && contentType == "text/plain" && trim(r.body) == "OK" ? (
  let altered = secret[:len(secret)-1] + (secret[len(secret)-1:] == "A" ? "B" : "A");
  let control = http.get(url, {"Authorization": "Bearer " + altered, "Accept": "text/plain"});
  let controlBody = type(control.json) == "map" ? control.json : {};
  control.status == 401 && lower(trim(split(control.headers["content-type"] ?? "", ";")[0])) == "application/json" &&
    type(controlBody?.errors) == "array" && any(controlBody.errors, { type(#) == "map" && (#.status ?? 0) == 401 }) ? {
    "result": "valid"
  } : {
    "result": "unknown",
    "reason": "Ping did not establish credential-specific authentication"
  }
) : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5`,
	Tests: []config.RuleTest{
		{
			Name:  "token with host",
			Input: "artifactoryRefToken := \"cmVmd5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7\"" + jfrogHost,
			Expect: []config.ExpectedFinding{
				{Secret: "cmVmd5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7", ComponentSets: []map[string]string{{"artifactory-jfrog-url": "mycompany.jfrog.io"}}},
			},
		},
		rulebuilder.NoMatch("token without host", `artifactoryRefToken := "cmVmd5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7"`),
		rulebuilder.NoMatch("low entropy", "lowEntropy := cmVmdXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"+jfrogHost),
		rulebuilder.NoMatch("wrong prefix case", `wrongStart := "cmVMd5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7"`+jfrogHost),
		rulebuilder.NoMatch("too short", `wrongLength := "cmVmd5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysj"`+jfrogHost),
		rulebuilder.NoMatch("inside a longer blob", "partOfAlongUnrelatedBlob gYnkgcmVmd5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7VyZSB2"+jfrogHost),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "artifactory-jfrog-url",
	Confidence:  "high",
	Description: "Detected a JFrog Artifactory host, used as a component of Artifactory token validation.",
	Regex:       `(?i)(?:^|[^a-z0-9-])([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.jfrog\.io)(?:$|[^a-z0-9-])`,
	Keywords:    []string{"jfrog.io"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) < 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("url", "ARTIFACTORY_URL=https://mycompany.jfrog.io", "mycompany.jfrog.io"),
		rulebuilder.MatchComponent("hyphenated host", "JFROG_URL=my-company-name.jfrog.io", "my-company-name.jfrog.io"),
		rulebuilder.MatchComponent("one-letter host", "host: a.jfrog.io", "a.jfrog.io"),
		rulebuilder.NoMatchComponent("leading hyphen", "JFROG_URL=-bad.jfrog.io"),
		rulebuilder.NoMatchComponent("trailing hyphen", "JFROG_URL=bad-.jfrog.io"),
		rulebuilder.NoMatch("hidden when scanned alone", "ARTIFACTORY_URL=https://mycompany.jfrog.io"),
	},
})
