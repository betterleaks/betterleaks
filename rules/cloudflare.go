package rules

import "github.com/betterleaks/betterleaks/v2/config"

const cloudflareAPITokenValidateExpr = `let account_token = finding["secret"] startsWith "cfat_";
let account_id = components["cloudflare-account-id.1"]?.secret ?? "";
account_token && account_id == "" ? {
  "result": "needs_validation",
  "reason": "Cloudflare account token verification requires an account ID"
} : (
  let r = http.get("https://api.cloudflare.com/client/v4" + (account_token ? "/accounts/" + account_id : "/user") + "/tokens/verify", {
    "Accept": "application/json",
    "Authorization": "Bearer " + finding["secret"]
  });
  let provider_result = r.json?.result ?? {};
  let token_status = provider_result["status"] ?? "";
  r.status == 200 && (r.json?.success ?? false) && token_status == "active" && (provider_result["id"] ?? "") != "" ? {
    "result": "valid",
    "analysis": {
      "token_id": provider_result["id"] ?? "",
      "token_type": account_token ? "account" : "user",
      "account_id": account_id,
      "not_before": provider_result["not_before"] ?? "",
      "expires_on": provider_result["expires_on"] ?? ""
    }
  } : r.status == 200 && token_status in ["disabled", "expired"] ? {
    "result": "revoked",
    "reason": token_status == "expired" ? "Token expired" : "Token disabled"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`

// Token details expose the allowed policy names when the credential can read
// its own token record. Unknown names remain metadata and grant no capability.
// https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/get/
// https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/methods/get/
const cloudflareAPITokenAnalyzeExpr = `let input = validation.analysis;
let token_id = input["token_id"] ?? "";
let token_type = input["token_type"] ?? "user";
let account_id = input["account_id"] ?? "";
let details_prefix = token_type == "account" ? "/accounts/" + account_id : "/user";
let details = http.get("https://api.cloudflare.com/client/v4" + details_prefix + "/tokens/" + token_id, {
  "Accept": "application/json",
  "Authorization": "Bearer " + finding["secret"]
});
let details_ok = details.status == 200 && (details.json?.success ?? false);
let token = details_ok ? (details.json?.result ?? {}) : {};
let policies = token["policies"] ?? [];
let permission_groups = flatten(map(policies, {#.effect == "allow" ? (#.permission_groups ?? []) : []}));
let permissions = map(permission_groups, {#.name ?? ""});
let can_crud = matchesAny(permissions, ["(?: Write| Edit)$"]);
let can_write = can_crud || matchesAny(permissions, ["(?: Revoke| Send)$", "^Cache Purge$"]);
{
  "reason": !details_ok ? "Cloudflare did not allow this token to read its policy details" : "",
  "identity": token_type == "account" && account_id != "" ? {
    "account": {"id": account_id}
  } : {},
  "metadata": {
    "token_id": token_id,
    "token_type": token_type,
    "token_name": token["name"] ?? "",
    "permissions": permissions,
    "policy_count": len(policies),
    "not_before": input["not_before"] ?? "",
    "expires_on": input["expires_on"] ?? ""
  },
  "capabilities": analysis.capabilities({
    "read": can_crud || matchesAny(permissions, [" Read$"]),
    "write": can_write,
    "create_credentials": matchesAny(permissions, [
      "^(?:Account )?API Tokens (?:Write|Edit)$",
      "^Access: (?:Keys|Service Tokens) (?:Write|Edit)$"
    ]),
    "manage_users": matchesAny(permissions, [
      "^(?:User )?Memberships (?:Write|Edit)$",
      "^Account Settings (?:Write|Edit)$"
    ])
  })
}`

var cloudflareGlobalAPIKeySamples = []string{
	`cloudflare_global_api_key = "d3d1443e0adc9c24564c6c5676d679d47e2ca"`, // betterleaks:allow
	`CLOUDFLARE_GLOBAL_API_KEY: 674538c7ecac77d064958a04a83d9e9db068c`,    // betterleaks:allow
	`cloudflare: "0574b9f43978174cc2cb9a1068681225433c4"`,                 // betterleaks:allow
}

var cloudflareLegacyAPITokenSamples = []string{
	`cloudflare_api_key = "Bu0rrK-lerk6y0Suqo1qSqlDDajOk61wZchCkje4"`, // betterleaks:allow
	`CLOUDFLARE_API_KEY: 5oK0U90ME14yU6CVxV90crvfqVlNH2wRKBwcLWDc`,    // betterleaks:allow
	`cloudflare: "oj9Yoyq0zmOyWmPPob1aoY5YSNNuJ0fbZSOURBlX"`,          // betterleaks:allow
}

var cloudflareOriginCAKeySamples = []string{
	`CLOUDFLARE_ORIGIN_CA: v1.0-aaa334dc886f30631ba0a610-0d98ef66290d7e50aac7c27b5986c99e6f3f1084c881d8ac0eae5de1d1aa0644076ff57022069b3237d19afe60ad045f207ef2b16387ee37b749441b2ae2e9ebe5b4606e846475d4a5`,
	`CLOUDFLARE_ORIGIN_CA: v1.0-15d20c7fccb4234ac5cdd756-d5c2630d1b606535cf9320ae7456b090e0896cec64169a92fae4e931ab0f72f111b2e4ffed5b2bb40f6fba6b2214df23b188a23693d59ce3fb0d28f7e89a2206d98271b002dac695ed`,
}

var cloudflareIdentifiers = []string{"cloudflare"}

var _ = Add(config.Rule{
	ID:          "cloudflare-account-id.1",
	Confidence:  "high",
	Description: "Detected a Cloudflare account ID, used as a component of Cloudflare API key validation.",
	Regex:       Assignment([]string{`account[_. -]*id`}, Hex("32")),
	Keywords:    []string{"account_id", "account-id", "account id", "accountid"},
	SkipReport:  true,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: "account_id=00000000000000000000000000000000",
			Expect: []config.ExpectedFinding{
				{Secret: "00000000000000000000000000000000"},
			},
		},
		{
			Name:  "true positive 2",
			Mode:  "match",
			Input: "CLOUDFLARE_ACCOUNT_ID=11111111111111111111111111111111",
			Expect: []config.ExpectedFinding{
				{Secret: "11111111111111111111111111111111"},
			},
		},
		{
			Name:  "true positive 3",
			Mode:  "match",
			Input: `accountId: "22222222222222222222222222222222"`,
			Expect: []config.ExpectedFinding{
				{Secret: "22222222222222222222222222222222"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  "cloudflare_access_key_id=33333333333333333333333333333333",
			Expect: []config.ExpectedFinding{},
		},
	},
})

var _ = Add(config.Rule{
	ID:          "cloudflare-global-api-key",
	Confidence:  "high",
	Description: "Detected a Cloudflare Global API Key, potentially compromising cloud application deployments and operational security.",
	Regex:       Assignment(cloudflareIdentifiers, `(?i)`+Hex("37")),
	Keywords:    cloudflareIdentifiers,
	FilterExpr:  `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("cloudflare assignment", `cloudflareToken = "1f7b169c846f218ab552fa82fbf86758bf5c9"`, "1f7b169c846f218ab552fa82fbf86758bf5c9"),
		Match("true positive 1", `cloudflare_global_api_key = "d3d1443e0adc9c24564c6c5676d679d47e2ca"`, "d3d1443e0adc9c24564c6c5676d679d47e2ca"),
		Match("true positive 2", "CLOUDFLARE_GLOBAL_API_KEY: 674538c7ecac77d064958a04a83d9e9db068c", "674538c7ecac77d064958a04a83d9e9db068c"),
		Match("true positive 3", `cloudflare: "0574b9f43978174cc2cb9a1068681225433c4"`, "0574b9f43978174cc2cb9a1068681225433c4"),
		NoMatch("false positive 1", `cloudflare_api_key = "Bu0rrK-lerk6y0Suqo1qSqlDDajOk61wZchCkje4"`),
		NoMatch("false positive 2", "CLOUDFLARE_API_KEY: 5oK0U90ME14yU6CVxV90crvfqVlNH2wRKBwcLWDc"),
		NoMatch("false positive 3", `cloudflare: "oj9Yoyq0zmOyWmPPob1aoY5YSNNuJ0fbZSOURBlX"`),
		NoMatch("false positive 4", "CLOUDFLARE_ORIGIN_CA: v1.0-aaa334dc886f30631ba0a610-0d98ef66290d7e50aac7c27b5986c99e6f3f1084c881d8ac0eae5de1d1aa0644076ff57022069b3237d19afe60ad045f207ef2b16387ee37b749441b2ae2e9ebe5b4606e846475d4a5"),
		NoMatch("false positive 5", "CLOUDFLARE_ORIGIN_CA: v1.0-15d20c7fccb4234ac5cdd756-d5c2630d1b606535cf9320ae7456b090e0896cec64169a92fae4e931ab0f72f111b2e4ffed5b2bb40f6fba6b2214df23b188a23693d59ce3fb0d28f7e89a2206d98271b002dac695ed"),
	},
})

var _ = Add(config.Rule{
	ID:           "cloudflare-api-key.1",
	Confidence:   "high",
	Description:  "Detected a Cloudflare API key version 1 (legacy format), potentially compromising cloud application deployments and operational security.",
	Regex:        Assignment(cloudflareIdentifiers, `(?i)`+AlphaNumericExtendedShort("40")),
	Keywords:     cloudflareIdentifiers,
	ValidateExpr: cloudflareAPITokenValidateExpr,
	AnalyzeExpr:  cloudflareAPITokenAnalyzeExpr,
	FilterExpr:   `entropy(finding["secret"]) < 3.5 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("cloudflare assignment", `cloudflareToken = "4v8l67z---wfu0y1vd_3l1cmfzxoud8et6xy88z3"`, "4v8l67z---wfu0y1vd_3l1cmfzxoud8et6xy88z3"),
		Match("true positive 1", `cloudflare_api_key = "Bu0rrK-lerk6y0Suqo1qSqlDDajOk61wZchCkje4"`, "Bu0rrK-lerk6y0Suqo1qSqlDDajOk61wZchCkje4"),
		Match("true positive 2", "CLOUDFLARE_API_KEY: 5oK0U90ME14yU6CVxV90crvfqVlNH2wRKBwcLWDc", "5oK0U90ME14yU6CVxV90crvfqVlNH2wRKBwcLWDc"),
		Match("true positive 3", `cloudflare: "oj9Yoyq0zmOyWmPPob1aoY5YSNNuJ0fbZSOURBlX"`, "oj9Yoyq0zmOyWmPPob1aoY5YSNNuJ0fbZSOURBlX"),
		NoMatch("false positive 1", `cloudflare_global_api_key = "d3d1443e0adc9c24564c6c5676d679d47e2ca"`),
		NoMatch("false positive 2", "CLOUDFLARE_GLOBAL_API_KEY: 674538c7ecac77d064958a04a83d9e9db068c"),
		NoMatch("false positive 3", `cloudflare: "0574b9f43978174cc2cb9a1068681225433c4"`),
		NoMatch("false positive 4", "CLOUDFLARE_ORIGIN_CA: v1.0-aaa334dc886f30631ba0a610-0d98ef66290d7e50aac7c27b5986c99e6f3f1084c881d8ac0eae5de1d1aa0644076ff57022069b3237d19afe60ad045f207ef2b16387ee37b749441b2ae2e9ebe5b4606e846475d4a5"),
		NoMatch("false positive 5", "CLOUDFLARE_ORIGIN_CA: v1.0-15d20c7fccb4234ac5cdd756-d5c2630d1b606535cf9320ae7456b090e0896cec64169a92fae4e931ab0f72f111b2e4ffed5b2bb40f6fba6b2214df23b188a23693d59ce3fb0d28f7e89a2206d98271b002dac695ed"),
	},
})

var _ = Add(config.Rule{
	ID:          "cloudflare-api-key.2",
	Confidence:  "high",
	Description: "Detected a Cloudflare API key version 2 (cfut/cfat format), potentially granting access to Cloudflare account and service resources.",
	Regex:       Token(`cf[ua]t_[A-Za-z0-9]{40}[a-f0-9]{8}`),
	Keywords:    []string{"cfut_", "cfat_"},
	Components: []config.Component{
		{RuleID: "cloudflare-account-id.1", Optional: true, Within: "5L"},
	},
	ValidateExpr: cloudflareAPITokenValidateExpr,
	AnalyzeExpr:  cloudflareAPITokenAnalyzeExpr,
	FilterExpr:   `entropy(finding["secret"]) < 3.0 || tokenRatio(finding["secret"]) >= 2.5`,
	Tests: []config.RuleTest{
		Match("bare secret", "cfut_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7li1f7b169c", "cfut_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7li1f7b169c"),
		Match("bare secret 2", "cfat_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7li1f7b169c", "cfat_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7li1f7b169c"),
		NoMatch("false positive 1", "cfut_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7l1f7b169c"),
		NoMatch("false positive 2", "cfat_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7liFDFFBABC"),
	},
})

var _ = Add(CloudflareOriginCAKey())

func CloudflareOriginCAKey() config.Rule {
	caIdentifiers := append(cloudflareIdentifiers, "v1.0-")
	r := config.Rule{
		Description: "Detected a Cloudflare Origin CA Key, potentially compromising cloud application deployments and operational security.",
		ID:          "cloudflare-origin-ca-key",
		Confidence:  "high",
		Regex:       Token(`v1\.0-` + Hex("24") + "-" + Hex("146")),
		Keywords:    caIdentifiers,
		FilterExpr:  `entropy(finding["secret"]) < 3.3 || tokenRatio(finding["secret"]) >= 2.5`,
	}
	r.Tests = []config.RuleTest{
		Match("cloudflare assignment", `cloudflareToken = "v1.0-aaa334dc886f30631ba0a610-0d98ef66290d7e50aac7c27b5986c99e6f3f1084c881d8ac0eae5de1d1aa0644076ff57022069b3237d19afe60ad045f207ef2b16387ee37b749441b2ae2e9ebe5b4606e846475d4a5"`, "v1.0-aaa334dc886f30631ba0a610-0d98ef66290d7e50aac7c27b5986c99e6f3f1084c881d8ac0eae5de1d1aa0644076ff57022069b3237d19afe60ad045f207ef2b16387ee37b749441b2ae2e9ebe5b4606e846475d4a5"),
		Match("true positive 1", "CLOUDFLARE_ORIGIN_CA: v1.0-aaa334dc886f30631ba0a610-0d98ef66290d7e50aac7c27b5986c99e6f3f1084c881d8ac0eae5de1d1aa0644076ff57022069b3237d19afe60ad045f207ef2b16387ee37b749441b2ae2e9ebe5b4606e846475d4a5", "v1.0-aaa334dc886f30631ba0a610-0d98ef66290d7e50aac7c27b5986c99e6f3f1084c881d8ac0eae5de1d1aa0644076ff57022069b3237d19afe60ad045f207ef2b16387ee37b749441b2ae2e9ebe5b4606e846475d4a5"),
		Match("true positive 2", "CLOUDFLARE_ORIGIN_CA: v1.0-15d20c7fccb4234ac5cdd756-d5c2630d1b606535cf9320ae7456b090e0896cec64169a92fae4e931ab0f72f111b2e4ffed5b2bb40f6fba6b2214df23b188a23693d59ce3fb0d28f7e89a2206d98271b002dac695ed", "v1.0-15d20c7fccb4234ac5cdd756-d5c2630d1b606535cf9320ae7456b090e0896cec64169a92fae4e931ab0f72f111b2e4ffed5b2bb40f6fba6b2214df23b188a23693d59ce3fb0d28f7e89a2206d98271b002dac695ed"),
		NoMatch("false positive 1", `cloudflare_global_api_key = "d3d1443e0adc9c24564c6c5676d679d47e2ca"`),
		NoMatch("false positive 2", "CLOUDFLARE_GLOBAL_API_KEY: 674538c7ecac77d064958a04a83d9e9db068c"),
		NoMatch("false positive 3", `cloudflare: "0574b9f43978174cc2cb9a1068681225433c4"`),
		NoMatch("false positive 4", `cloudflare_api_key = "Bu0rrK-lerk6y0Suqo1qSqlDDajOk61wZchCkje4"`),
		NoMatch("false positive 5", "CLOUDFLARE_API_KEY: 5oK0U90ME14yU6CVxV90crvfqVlNH2wRKBwcLWDc"),
		NoMatch("false positive 6", `cloudflare: "oj9Yoyq0zmOyWmPPob1aoY5YSNNuJ0fbZSOURBlX"`),
	}
	return r
}
