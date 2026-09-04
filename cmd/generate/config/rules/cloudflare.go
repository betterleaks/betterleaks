package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

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
let can_crud = filter.matchesAny(permissions, ["(?: Write| Edit)$"]);
let can_write = can_crud || filter.matchesAny(permissions, ["(?: Revoke| Send)$", "^Cache Purge$"]);
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
    "policy_count": size(policies),
    "not_before": input["not_before"] ?? "",
    "expires_on": input["expires_on"] ?? ""
  },
  "capabilities": analysis.capabilities({
    "read": can_crud || filter.matchesAny(permissions, [" Read$"]),
    "write": can_write,
    "create_credentials": filter.matchesAny(permissions, [
      "^(?:Account )?API Tokens (?:Write|Edit)$",
      "^Access: (?:Keys|Service Tokens) (?:Write|Edit)$"
    ]),
    "manage_users": filter.matchesAny(permissions, [
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

func CloudflareAccountIDV1() *config.Rule {
	r := config.Rule{
		RuleID:      "cloudflare-account-id.1",
		Confidence:  "high",
		Description: "Detected a Cloudflare account ID, used as a component of Cloudflare API key validation.",
		Regex:       utils.GenerateSemiGenericRegex([]string{`account[_. -]*id`}, utils.Hex("32"), false),
		Keywords:    []string{"account_id", "account-id", "account id", "accountid"},
		SkipReport:  true,
	}

	return utils.Validate(r, []string{
		`account_id=00000000000000000000000000000000`,
		`CLOUDFLARE_ACCOUNT_ID=11111111111111111111111111111111`,
		`accountId: "22222222222222222222222222222222"`,
	}, []string{
		`cloudflare_access_key_id=33333333333333333333333333333333`,
	})
}

func CloudflareGlobalAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "cloudflare-global-api-key",
		Confidence:  "high",
		Description: "Detected a Cloudflare Global API Key, potentially compromising cloud application deployments and operational security.",
		Regex:       utils.GenerateSemiGenericRegex(cloudflareIdentifiers, utils.Hex("37"), true),
		Keywords:    cloudflareIdentifiers,
		Filter:      `filter.entropy(finding["secret"]) < 3.3 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	tps := utils.GenerateSampleSecrets("cloudflare", secrets.NewSecretWithEntropy(utils.Hex("37"), 3.3))
	tps = append(tps, cloudflareGlobalAPIKeySamples...)
	fps := append(cloudflareLegacyAPITokenSamples, cloudflareOriginCAKeySamples...)

	return utils.Validate(r, tps, fps)
}

func CloudflareAPIKeyV1() *config.Rule {
	r := config.Rule{
		RuleID:       "cloudflare-api-key.1",
		Confidence:   "high",
		Description:  "Detected a Cloudflare API key version 1 (legacy format), potentially compromising cloud application deployments and operational security.",
		Regex:        utils.GenerateSemiGenericRegex(cloudflareIdentifiers, utils.AlphaNumericExtendedShort("40"), true),
		Keywords:     cloudflareIdentifiers,
		ValidateExpr: cloudflareAPITokenValidateExpr,
		AnalyzeExpr:  cloudflareAPITokenAnalyzeExpr,
		Filter:       `filter.entropy(finding["secret"]) < 3.5 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	tps := utils.GenerateSampleSecrets("cloudflare", secrets.NewSecretWithEntropy(utils.AlphaNumericExtendedShort("40"), 3.5))
	tps = append(tps, cloudflareLegacyAPITokenSamples...)
	fps := append(cloudflareGlobalAPIKeySamples, cloudflareOriginCAKeySamples...)

	return utils.Validate(r, tps, fps)
}

func CloudflareAPIKeyV2() *config.Rule {
	r := config.Rule{
		RuleID:      "cloudflare-api-key.2",
		Confidence:  "high",
		Description: "Detected a Cloudflare API key version 2 (cfut/cfat format), potentially granting access to Cloudflare account and service resources.",
		Regex:       utils.GenerateUniqueTokenRegex(`cf[ua]t_[A-Za-z0-9]{40}[a-f0-9]{8}`, false),
		Keywords:    []string{"cfut_", "cfat_"},
		Components: []*config.Component{
			{RuleID: "cloudflare-account-id.1", Optional: true, Within: "5L"},
		},
		ValidateExpr: cloudflareAPITokenValidateExpr,
		AnalyzeExpr:  cloudflareAPITokenAnalyzeExpr,
		Filter:       `filter.entropy(finding["secret"]) < 3.0 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	userToken := "cfut_" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("40"), 3.0) + secrets.NewSecret(utils.Hex("8"))
	accountToken := "cfat_" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("40"), 3.0) + secrets.NewSecret(utils.Hex("8"))
	fps := []string{
		"cfut_" + secrets.NewSecret(utils.AlphaNumeric("39")) + secrets.NewSecret(utils.Hex("8")),
		"cfat_" + secrets.NewSecret(utils.AlphaNumeric("40")) + secrets.NewSecret(`[A-F]{8}`),
	}
	return utils.Validate(r, []string{userToken, accountToken}, fps)
}

func CloudflareOriginCAKey() *config.Rule {
	caIdentifiers := append(cloudflareIdentifiers, "v1.0-")
	r := config.Rule{
		Description: "Detected a Cloudflare Origin CA Key, potentially compromising cloud application deployments and operational security.",
		RuleID:      "cloudflare-origin-ca-key",
		Confidence:  "high",
		Regex:       utils.GenerateUniqueTokenRegex(`v1\.0-`+utils.Hex("24")+"-"+utils.Hex("146"), false),
		Keywords:    caIdentifiers,
		Filter:      `filter.entropy(finding["secret"]) < 3.3 || filter.tokenRatio(finding["secret"]) >= 2.5`,
	}

	tps := utils.GenerateSampleSecrets("cloudflare", "v1.0-aaa334dc886f30631ba0a610-0d98ef66290d7e50aac7c27b5986c99e6f3f1084c881d8ac0eae5de1d1aa0644076ff57022069b3237d19afe60ad045f207ef2b16387ee37b749441b2ae2e9ebe5b4606e846475d4a5")
	tps = append(tps, cloudflareOriginCAKeySamples...)
	fps := append(cloudflareGlobalAPIKeySamples, cloudflareLegacyAPITokenSamples...)

	return utils.Validate(r, tps, fps)
}
