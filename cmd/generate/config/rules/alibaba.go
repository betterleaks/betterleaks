package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func AlibabaAccessKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "alibaba-access-key-id",
		Description: "Detected an Alibaba Cloud AccessKey ID, posing a risk of unauthorized cloud resource access and potential data compromise.",
		Regex:       regexp.MustCompile(`\b(LTAI[A-Za-z0-9]{17,21})\b`),
		Keywords:    []string{"LTAI"},
		SkipReport:  true,
		Filter:      `filter.entropy(finding["secret"]) < 3.0`,
	}

	// validate
	tps := []string{
		"LTAI8x2NiGqfyJGx7eLDhp12",
		"LTAI5GqyJGhp12ad31L5hpix",
	}
	return utils.Validate(r, tps, nil)
}

// TODO
func AlibabaSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "alibaba-secret-key",
		Description: "Discovered a potential Alibaba Cloud Secret Key, potentially allowing unauthorized operations and data access within Alibaba Cloud.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"alibaba", "aliyun", "secret", "key"}, `[A-Za-z0-9]{30}`, true),
		Keywords:    []string{"alibaba", "aliyun"},
		RequiredRules: []*config.Required{
			{
				RuleID:      "alibaba-access-key-id",
				WithinLines: utils.Ptr(5),
			},
		},
		ValidateCEL: alibabaAccessKeyValidationCEL("alibaba-access-key-id", "", ""),
		Filter:      `filter.entropy(finding["secret"]) < 3.5`,
	}

	// validate
	tps := []string{
		`alibaba_access_key_secret = 7jkWdTjKLnSlGddwPR5gBn65PHcZG6`,
	}
	return utils.Validate(r, tps, nil)
}

func AlibabaSTSAccessKeyID() *config.Rule {
	r := config.Rule{
		RuleID:      "alibaba-sts-access-key-id",
		Description: "Detected an Alibaba Cloud STS AccessKey ID, used as a component of the alibaba-sts-access-key-secret composite rule.",
		Regex:       regexp.MustCompile(`\b(STS\.[A-Za-z0-9]{16,64})\b`),
		Keywords:    []string{"sts."},
		SkipReport:  true,
		Filter:      `filter.entropy(finding["secret"]) < 3.0`,
	}

	tps := []string{
		`alibaba_sts_access_key_id = STS.NTKaenSkmLhG4HpM576UV`,
		`alibaba cloud sts access key id: STS.FJ6EMcS1JLZgAcBJSTDG1Z4CE`,
	}
	fps := []string{
		`STS.short`,
	}
	return utils.Validate(r, tps, fps)
}

func AlibabaSTSSecurityToken() *config.Rule {
	r := config.Rule{
		RuleID:      "alibaba-sts-security-token",
		Description: "Detected an Alibaba Cloud STS security token, used as a component of the alibaba-sts-access-key-secret composite rule.",
		// Regex:       regexp.MustCompile(`(?i)\b(?:security[\s_-]*token|sts[\s_-]*token|x[\s_-]*oss[\s_-]*security[\s_-]*token|alibaba[\s_-]*cloud[\s_-]*security[\s_-]*token|aliyun[\s_-]*security[\s_-]*token)(?:.|[\n\r]){0,16}?(?:=|:|["']\s*:\s*["'])\s*["']?(CAIS[A-Za-z0-9+/_=-]{20,1000}[A-Za-z0-9+/_=-]{0,24})(?:["'\s,;}&\]]|$)`),
		Regex:      utils.GenerateSemiGenericRegex([]string{"alibaba", "aliyun", "secret", "key"}, `CAIS[A-Za-z0-9+/_=-]{20,1000}[A-Za-z0-9+/_=-]{0,24}`, true),
		Keywords:   []string{"alibaba", "aliyun", "cais"},
		SkipReport: true,
		Filter:     `filter.entropy(finding["secret"]) < 3.5`,
	}

	tps := []string{
		`alibaba_token = "CAISuwJ1q6Ft5B2yu9Kiaa5E0VnVJ8q2o3P4r5S6t7U8v9W0xYz"`,
		`ALIBABA__TOKEN=CAIS/gF1q6Ft5B2yfSjIr5eDA9xjJCcl57eKC7A3ThnJA`,
	}
	fps := []string{
		`token = "CAISuwJ1q6Ft5B2yu9Kiaa5E0VnVJ8q2o3P4r5S6t7U8v9W0xYz"`,
	}
	return utils.Validate(r, tps, fps)
}

func AlibabaSTSAccessKeySecret() *config.Rule {
	r := config.Rule{
		RuleID:      "alibaba-sts-access-key-secret",
		Description: "Detected an Alibaba Cloud STS AccessKey secret, which may allow temporary Alibaba Cloud API access when paired with an STS AccessKey ID and security token.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"alibaba", "aliyun", "secret", "key"}, `[A-Za-z0-9]{30,64}`, true),
		Keywords:    []string{"alibaba", "aliyun"},
		RequiredRules: []*config.Required{
			{
				RuleID:      "alibaba-sts-access-key-id",
				WithinLines: utils.Ptr(10),
			},
			{
				RuleID:      "alibaba-sts-security-token",
				WithinLines: utils.Ptr(10),
			},
		},
		ValidateCEL: alibabaAccessKeyValidationCEL("alibaba-sts-access-key-id", "alibaba-sts-security-token", "SecurityToken="),
		Filter:      `filter.entropy(finding["secret"]) < 3.5`,
	}

	tps := []string{
		`aliyun_sts_access_key_secret: 6itECZnhbG2RU6ktTSBSd6JxeLHKPWyBtSS62`,
	}
	fps := []string{
		`AccessKeySecret=short`,
	}
	return utils.Validate(r, tps, fps)
}

func alibabaAccessKeyValidationCEL(accessKeyIDCapture, securityTokenCapture, securityTokenParam string) string {
	if securityTokenCapture == "" {
		return `cel.bind(ts, time.nowRFC3339(),
  cel.bind(nonce, time.nowUnix(),
    cel.bind(params,
      "AccessKeyId=" + strings.urlQueryEscape(captures["` + accessKeyIDCapture + `"]) +
      "&Action=GetCallerIdentity&Format=JSON&SignatureMethod=HMAC-SHA1&SignatureNonce=" + nonce +
      "&SignatureVersion=1.0&Timestamp=" + strings.urlQueryEscape(ts) + "&Version=2015-04-01",
      cel.bind(string_to_sign, "GET&%2F&" + strings.urlQueryEscape(params).replace("+", "%20").replace("*", "%2A").replace("%7E", "~"),
        cel.bind(sig, strings.urlQueryEscape(base64.encode(crypto.hmacSha1(bytes(finding["secret"] + "&"), bytes(string_to_sign)))),
          cel.bind(r,
            http.get("https://sts.aliyuncs.com/?" + params + "&Signature=" + sig, {
              "Accept": "application/json"
            }),
            r.status == 200 && r.body.contains("\"Arn\"") ? {
              "result": "valid"
            } : r.status in [401, 403] || r.body.contains("InvalidAccessKeyId") || r.body.contains("SignatureDoesNotMatch") ? {
              "result": "invalid",
              "reason": "Unauthorized"
            } : validate.unknown(r)
          )
        )
      )
    )
  )
)`
	}

	return `cel.bind(ts, time.nowRFC3339(),
  cel.bind(nonce, time.nowUnix(),
    cel.bind(params,
      "AccessKeyId=" + strings.urlQueryEscape(captures["` + accessKeyIDCapture + `"]) +
      "&Action=GetCallerIdentity&Format=JSON&` + securityTokenParam + `" + strings.urlQueryEscape(captures["` + securityTokenCapture + `"]) +
      "&SignatureMethod=HMAC-SHA1&SignatureNonce=" + nonce +
      "&SignatureVersion=1.0&Timestamp=" + strings.urlQueryEscape(ts) + "&Version=2015-04-01",
      cel.bind(string_to_sign, "GET&%2F&" + strings.urlQueryEscape(params).replace("+", "%20").replace("*", "%2A").replace("%7E", "~"),
        cel.bind(sig, strings.urlQueryEscape(base64.encode(crypto.hmacSha1(bytes(finding["secret"] + "&"), bytes(string_to_sign)))),
          cel.bind(r,
            http.get("https://sts.aliyuncs.com/?" + params + "&Signature=" + sig, {
              "Accept": "application/json"
            }),
            r.status == 200 && r.body.contains("\"Arn\"") ? {
              "result": "valid"
            } : r.status in [401, 403] || r.body.contains("InvalidAccessKeyId") || r.body.contains("SignatureDoesNotMatch") ? {
              "result": "invalid",
              "reason": "Unauthorized"
            } : validate.unknown(r)
          )
        )
      )
    )
  )
)`
}
