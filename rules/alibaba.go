package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// https://www.alibabacloud.com/help/en/ram/developer-reference/api-sts-2015-04-01-getcalleridentity
const alibabaAnalyzeExpr = `let input = validation.analysis;
{
  "identity": {
    "id": input["principal_id"] ?? "",
    "account": {"id": input["account_id"] ?? ""}
  },
  "capabilities": [],
  "metadata": fromPairs(filter(toPairs({
    "arn": input["arn"] ?? "",
    "identity_type": input["identity_type"] ?? ""
  }), {#[1] != nil && #[1] != "" && #[1] != []}))
}`

var _ = rulebuilder.Add(config.Rule{
	ID:          "alibaba-access-key-id",
	Confidence:  "high",
	Description: "Detected an Alibaba Cloud AccessKey ID, posing a risk of unauthorized cloud resource access and potential data compromise.",
	Regex:       `\b(LTAI[A-Za-z0-9]{17,21})\b`,
	Keywords:    []string{"ltai"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) < 3.0`,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("bare secret", "LTAI8x2NiGqfyJGx7eLDhp12", "LTAI8x2NiGqfyJGx7eLDhp12"),
		rulebuilder.MatchComponent("bare secret 2", "LTAI5GqyJGhp12ad31L5hpix", "LTAI5GqyJGhp12ad31L5hpix"),
	},
})

// TODO
var _ = rulebuilder.Add(config.Rule{
	ID:          "alibaba-secret-key",
	Confidence:  "high",
	Description: "Discovered a potential Alibaba Cloud Secret Key, potentially allowing unauthorized operations and data access within Alibaba Cloud.",
	Regex:       rulebuilder.Assignment([]string{"alibaba", "aliyun", "secret", "key"}, `(?i)[A-Za-z0-9]{30}`),
	Keywords:    []string{"alibaba", "aliyun"},
	Components: []config.Component{
		{
			RuleID: "alibaba-access-key-id",
			Within: "5L",
		},
	},
	ValidateExpr: alibabaAccessKeyValidationExpr("alibaba-access-key-id", "", ""),
	FilterExpr:   `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	AnalyzeExpr:  alibabaAnalyzeExpr,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "alibaba_access_key_secret = 7jkWdTjKLnSlGddwPR5gBn65PHcZG6\nLTAI8x2NiGqfyJGx7eLDhp12",
			Expect: []config.ExpectedFinding{
				{Secret: "7jkWdTjKLnSlGddwPR5gBn65PHcZG6", ComponentSets: []map[string]string{{"alibaba-access-key-id": "LTAI8x2NiGqfyJGx7eLDhp12"}}},
			},
		},
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "alibaba-sts-access-key-id",
	Confidence:  "high",
	Description: "Detected an Alibaba Cloud STS AccessKey ID, used as a component of the alibaba-sts-access-key-secret composite rule.",
	Regex:       `\b(STS\.[A-Za-z0-9]{16,64})\b`,
	Keywords:    []string{"sts."},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) < 3.0`,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "alibaba_sts_access_key_id = STS.NTKaenSkmLhG4HpM576UV", "STS.NTKaenSkmLhG4HpM576UV"),
		rulebuilder.MatchComponent("true positive 2", "alibaba cloud sts access key id: STS.FJ6EMcS1JLZgAcBJSTDG1Z4CE", "STS.FJ6EMcS1JLZgAcBJSTDG1Z4CE"),
		rulebuilder.NoMatchComponent("false positive 1", "STS.short"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "alibaba-sts-security-token",
	Confidence:  "high",
	Description: "Detected an Alibaba Cloud STS security token, used as a component of the alibaba-sts-access-key-secret composite rule.",
	// Regex:       regexp.MustCompile(`(?i)\b(?:security[\s_-]*token|sts[\s_-]*token|x[\s_-]*oss[\s_-]*security[\s_-]*token|alibaba[\s_-]*cloud[\s_-]*security[\s_-]*token|aliyun[\s_-]*security[\s_-]*token)(?:.|[\n\r]){0,16}?(?:=|:|["']\s*:\s*["'])\s*["']?(CAIS[A-Za-z0-9+/_=-]{20,1000}[A-Za-z0-9+/_=-]{0,24})(?:["'\s,;}&\]]|$)`),
	Regex:      rulebuilder.Assignment([]string{"alibaba", "aliyun", "secret", "key"}, `(?i)CAIS[A-Za-z0-9+/_=-]{20,1000}[A-Za-z0-9+/_=-]{0,24}`),
	Keywords:   []string{"alibaba", "aliyun", "cais"},
	SkipReport: true,
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", `alibaba_token = "CAISuwJ1q6Ft5B2yu9Kiaa5E0VnVJ8q2o3P4r5S6t7U8v9W0xYz"`, "CAISuwJ1q6Ft5B2yu9Kiaa5E0VnVJ8q2o3P4r5S6t7U8v9W0xYz"),
		rulebuilder.MatchComponent("true positive 2", "ALIBABA__TOKEN=CAIS/gF1q6Ft5B2yfSjIr5eDA9xjJCcl57eKC7A3ThnJA", "CAIS/gF1q6Ft5B2yfSjIr5eDA9xjJCcl57eKC7A3ThnJA"),
		rulebuilder.NoMatchComponent("false positive 1", `token = "CAISuwJ1q6Ft5B2yu9Kiaa5E0VnVJ8q2o3P4r5S6t7U8v9W0xYz"`),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "alibaba-sts-access-key-secret",
	Confidence:  "high",
	Description: "Detected an Alibaba Cloud STS AccessKey secret, which may allow temporary Alibaba Cloud API access when paired with an STS AccessKey ID and security token.",
	Regex:       rulebuilder.Assignment([]string{"alibaba", "aliyun", "secret", "key"}, `(?i)[A-Za-z0-9]{30,64}`),
	Keywords:    []string{"alibaba", "aliyun"},
	Components: []config.Component{
		{
			RuleID: "alibaba-sts-access-key-id",
			Within: "10L",
		},
		{
			RuleID: "alibaba-sts-security-token",
			Within: "10L",
		},
	},
	ValidateExpr: alibabaAccessKeyValidationExpr("alibaba-sts-access-key-id", "alibaba-sts-security-token", "SecurityToken"),
	FilterExpr:   `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	AnalyzeExpr:  alibabaAnalyzeExpr,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "aliyun_sts_access_key_secret: 6itECZnhbG2RU6ktTSBSd6JxeLHKPWyBtSS62\nalibaba_sts_access_key_id = STS.NTKaenSkmLhG4HpM576UV\nalibaba_token = \"CAISuwJ1q6Ft5B2yu9Kiaa5E0VnVJ8q2o3P4r5S6t7U8v9W0xYz\"",
			Expect: []config.ExpectedFinding{
				{Secret: "6itECZnhbG2RU6ktTSBSd6JxeLHKPWyBtSS62", ComponentSets: []map[string]string{{"alibaba-sts-access-key-id": "STS.NTKaenSkmLhG4HpM576UV", "alibaba-sts-security-token": "CAISuwJ1q6Ft5B2yu9Kiaa5E0VnVJ8q2o3P4r5S6t7U8v9W0xYz"}}},
				{Secret: "CAISuwJ1q6Ft5B2yu9Kiaa5E0VnVJ8q2o3P4r5S6t7U8v9W0xYz", ComponentSets: []map[string]string{{"alibaba-sts-access-key-id": "STS.NTKaenSkmLhG4HpM576UV", "alibaba-sts-security-token": "CAISuwJ1q6Ft5B2yu9Kiaa5E0VnVJ8q2o3P4r5S6t7U8v9W0xYz"}}},
			},
		},
		rulebuilder.NoMatch("false positive 1", "AccessKeySecret=short"),
	},
})

func alibabaAccessKeyValidationExpr(accessKeyIDCapture, securityTokenCapture, securityTokenParam string) string {
	securityTokenExpr := ""
	if securityTokenCapture != "" {
		securityTokenExpr = `
  "&` + securityTokenParam + `=" + strings.urlQueryEscape((components["` + securityTokenCapture + `"]?.secret ?? "")) +`
	}

	return `let ts = time.nowRFC3339();
let nonce = time.nowUnix();
let params =
  "AccessKeyId=" + strings.urlQueryEscape((components["` + accessKeyIDCapture + `"]?.secret ?? "")) +
  "&Action=GetCallerIdentity&Format=JSON" +` + securityTokenExpr + `
  "&SignatureMethod=HMAC-SHA1&SignatureNonce=" + nonce +
  "&SignatureVersion=1.0&Timestamp=" + strings.urlQueryEscape(ts) + "&Version=2015-04-01";
let string_to_sign = "GET&%2F&" + replace(replace(replace(strings.urlQueryEscape(params), "+", "%20"), "*", "%2A"), "%7E", "~");
let sig = strings.urlQueryEscape(base64.encode(crypto.hmacSha1(bytes(finding["secret"] + "&"), bytes(string_to_sign))));
let r = http.get("https://sts.aliyuncs.com/?" + params + "&Signature=" + sig, {
  "Accept": "application/json"
});
let body = type(r.json) == "map" ? r.json : {};
r.status == 200 && type(body?.Arn) == "string" && body.Arn != "" && type(body?.AccountId) == "string" && body.AccountId != "" ? {
  "result": "valid", "analysis": {
    "account_id": body.AccountId, "arn": body.Arn,
    "principal_id": type(body?.PrincipalId) == "string" ? body.PrincipalId : "",
    "identity_type": type(body?.IdentityType) == "string" ? body.IdentityType : ""
  }
} : r.status == 401 || (type(body?.Code) == "string" && (body.Code startsWith "InvalidAccessKeyId" || body.Code == "SignatureDoesNotMatch")) ? {
  "result": "invalid",
  "reason": "Unauthorized"
} : validate.unknown(r)`
}
