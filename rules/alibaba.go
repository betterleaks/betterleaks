package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "alibaba-access-key-id",
	Confidence:  "high",
	Description: "Detected an Alibaba Cloud AccessKey ID, posing a risk of unauthorized cloud resource access and potential data compromise.",
	Regex:       `\b(LTAI[A-Za-z0-9]{17,21})\b`,
	Keywords:    []string{"LTAI"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) < 3.0`,
	Tests: []config.RuleTest{
		{
			Name:  "bare secret",
			Mode:  "match",
			Input: "LTAI8x2NiGqfyJGx7eLDhp12",
			Expect: []config.ExpectedFinding{
				{Secret: "LTAI8x2NiGqfyJGx7eLDhp12"},
			},
		},
		{
			Name:  "bare secret 2",
			Mode:  "match",
			Input: "LTAI5GqyJGhp12ad31L5hpix",
			Expect: []config.ExpectedFinding{
				{Secret: "LTAI5GqyJGhp12ad31L5hpix"},
			},
		},
	},
})

// TODO
var _ = Add(config.Rule{
	ID:          "alibaba-secret-key",
	Confidence:  "high",
	Description: "Discovered a potential Alibaba Cloud Secret Key, potentially allowing unauthorized operations and data access within Alibaba Cloud.",
	Regex:       Assignment([]string{"alibaba", "aliyun", "secret", "key"}, `(?i)[A-Za-z0-9]{30}`),
	Keywords:    []string{"alibaba", "aliyun"},
	Components: []config.Component{
		{
			RuleID: "alibaba-access-key-id",
			Within: "5L",
		},
	},
	ValidateExpr: alibabaAccessKeyValidationExpr("alibaba-access-key-id", "", ""),
	FilterExpr:   `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
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

var _ = Add(config.Rule{
	ID:          "alibaba-sts-access-key-id",
	Confidence:  "high",
	Description: "Detected an Alibaba Cloud STS AccessKey ID, used as a component of the alibaba-sts-access-key-secret composite rule.",
	Regex:       `\b(STS\.[A-Za-z0-9]{16,64})\b`,
	Keywords:    []string{"sts."},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) < 3.0`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: "alibaba_sts_access_key_id = STS.NTKaenSkmLhG4HpM576UV",
			Expect: []config.ExpectedFinding{
				{Secret: "STS.NTKaenSkmLhG4HpM576UV"},
			},
		},
		{
			Name:  "true positive 2",
			Mode:  "match",
			Input: "alibaba cloud sts access key id: STS.FJ6EMcS1JLZgAcBJSTDG1Z4CE",
			Expect: []config.ExpectedFinding{
				{Secret: "STS.FJ6EMcS1JLZgAcBJSTDG1Z4CE"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  "STS.short",
			Expect: []config.ExpectedFinding{},
		},
	},
})

var _ = Add(config.Rule{
	ID:          "alibaba-sts-security-token",
	Confidence:  "high",
	Description: "Detected an Alibaba Cloud STS security token, used as a component of the alibaba-sts-access-key-secret composite rule.",
	// Regex:       regexp.MustCompile(`(?i)\b(?:security[\s_-]*token|sts[\s_-]*token|x[\s_-]*oss[\s_-]*security[\s_-]*token|alibaba[\s_-]*cloud[\s_-]*security[\s_-]*token|aliyun[\s_-]*security[\s_-]*token)(?:.|[\n\r]){0,16}?(?:=|:|["']\s*:\s*["'])\s*["']?(CAIS[A-Za-z0-9+/_=-]{20,1000}[A-Za-z0-9+/_=-]{0,24})(?:["'\s,;}&\]]|$)`),
	Regex:      Assignment([]string{"alibaba", "aliyun", "secret", "key"}, `(?i)CAIS[A-Za-z0-9+/_=-]{20,1000}[A-Za-z0-9+/_=-]{0,24}`),
	Keywords:   []string{"alibaba", "aliyun", "cais"},
	SkipReport: true,
	FilterExpr: `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: `alibaba_token = "CAISuwJ1q6Ft5B2yu9Kiaa5E0VnVJ8q2o3P4r5S6t7U8v9W0xYz"`,
			Expect: []config.ExpectedFinding{
				{Secret: "CAISuwJ1q6Ft5B2yu9Kiaa5E0VnVJ8q2o3P4r5S6t7U8v9W0xYz"},
			},
		},
		{
			Name:  "true positive 2",
			Mode:  "match",
			Input: "ALIBABA__TOKEN=CAIS/gF1q6Ft5B2yfSjIr5eDA9xjJCcl57eKC7A3ThnJA",
			Expect: []config.ExpectedFinding{
				{Secret: "CAIS/gF1q6Ft5B2yfSjIr5eDA9xjJCcl57eKC7A3ThnJA"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  `token = "CAISuwJ1q6Ft5B2yu9Kiaa5E0VnVJ8q2o3P4r5S6t7U8v9W0xYz"`,
			Expect: []config.ExpectedFinding{},
		},
	},
})

var _ = Add(config.Rule{
	ID:          "alibaba-sts-access-key-secret",
	Confidence:  "high",
	Description: "Detected an Alibaba Cloud STS AccessKey secret, which may allow temporary Alibaba Cloud API access when paired with an STS AccessKey ID and security token.",
	Regex:       Assignment([]string{"alibaba", "aliyun", "secret", "key"}, `(?i)[A-Za-z0-9]{30,64}`),
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
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "aliyun_sts_access_key_secret: 6itECZnhbG2RU6ktTSBSd6JxeLHKPWyBtSS62\nalibaba_sts_access_key_id = STS.NTKaenSkmLhG4HpM576UV\nalibaba_token = \"CAISuwJ1q6Ft5B2yu9Kiaa5E0VnVJ8q2o3P4r5S6t7U8v9W0xYz\"",
			Expect: []config.ExpectedFinding{
				{Secret: "6itECZnhbG2RU6ktTSBSd6JxeLHKPWyBtSS62", ComponentSets: []map[string]string{{"alibaba-sts-access-key-id": "STS.NTKaenSkmLhG4HpM576UV", "alibaba-sts-security-token": "CAISuwJ1q6Ft5B2yu9Kiaa5E0VnVJ8q2o3P4r5S6t7U8v9W0xYz"}}},
				{Secret: "CAISuwJ1q6Ft5B2yu9Kiaa5E0VnVJ8q2o3P4r5S6t7U8v9W0xYz", ComponentSets: []map[string]string{{"alibaba-sts-access-key-id": "STS.NTKaenSkmLhG4HpM576UV", "alibaba-sts-security-token": "CAISuwJ1q6Ft5B2yu9Kiaa5E0VnVJ8q2o3P4r5S6t7U8v9W0xYz"}}},
			},
		},
		NoMatch("false positive 1", "AccessKeySecret=short"),
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
  "AccessKeyId=" + strings.urlQueryEscape((components["` + accessKeyIDCapture + `"]?.secret ?? "")) +` + securityTokenExpr + `
  "&Action=GetCallerIdentity&Format=JSON&SignatureMethod=HMAC-SHA1&SignatureNonce=" + nonce +
  "&SignatureVersion=1.0&Timestamp=" + strings.urlQueryEscape(ts) + "&Version=2015-04-01";
let string_to_sign = "GET&%2F&" + replace(replace(replace(strings.urlQueryEscape(params), "+", "%20"), "*", "%2A"), "%7E", "~");
let sig = strings.urlQueryEscape(base64.encode(crypto.hmacSha1(bytes(finding["secret"] + "&"), bytes(string_to_sign))));
let r = http.get("https://sts.aliyuncs.com/?" + params + "&Signature=" + sig, {
  "Accept": "application/json"
});
r.status == 200 && (r.body contains "\"Arn\"") ? {
  "result": "valid"
} : r.status in [401, 403] || (r.body contains "InvalidAccessKeyId") || (r.body contains "SignatureDoesNotMatch") ? {
  "result": "invalid",
  "reason": "Unauthorized"
} : validate.unknown(r)`
}
