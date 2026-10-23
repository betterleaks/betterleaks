package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

// Labelbox and Recursion keys are a prefix plus 32 random bytes in unpadded base64url.
// The last character carries 4 data bits and 2 zero bits, so it is one of 16 values.
const labelboxKeyBody = `[\w-]{42}[AEIMQUYcgkosw048]`

// https://docs.labelbox.com/reference/user
// Unknown, revoked, and expired keys all get 200 with a null user.
const labelboxValidateExpr = `let r = http.post("https://api.labelbox.com/graphql", {"Authorization": "Bearer " + finding["secret"], "Content-Type": "application/json"}, "{\"query\":\"query { user { id email organization { id name } } }\"}");
let user = type(r.json) == "map" && type(r.json?.data) == "map" ? r.json?.data?.user : nil;
r.status == 200 && type(user) == "map" && (user?.id ?? "") != "" && len(r.json?.errors ?? []) == 0 ? {
  "result": "valid",
  "analysis": {
    "identity": {
      "id": string(user?.id ?? ""),
      "email": string(user?.email ?? ""),
      "account": type(user?.organization) == "map" ? {
        "id": string(user?.organization?.id ?? ""),
        "name": string(user?.organization?.name ?? "")
      } : {}
    }
  }
} : (r.status == 200 && type(r.json) == "map" && type(r.json?.data) == "map" && user == nil && len(r.json?.errors ?? []) == 0) || r.status == 401 ? {
  "result": "invalid", "reason": "Invalid, revoked, or expired API key"
} : validate.unknown(r)`

const labelboxAnalyzeExpr = identityOnlyAnalyzeExpr

// LabelboxAPIKey detects Labelbox API keys.
// https://docs.labelbox.com/reference/create-api-key
func LabelboxAPIKey() *config.Rule {
	r := config.Rule{
		ID:           "labelbox-api-key",
		Confidence:   "high",
		Description:  "Detected a Labelbox API key, which can read and modify projects, datasets, and annotations in a Labelbox organization.",
		Regex:        utils.GenerateUniqueTokenRegex(`lbx_`+labelboxKeyBody, false),
		Keywords:     []string{"lbx_"},
		FilterExpr:   utils.MinEntropy(3.5),
		ValidateExpr: labelboxValidateExpr,
		AnalyzeExpr:  labelboxAnalyzeExpr,
	}

	tps := utils.GenerateSampleSecrets("labelbox", "lbx_"+secrets.NewSecretWithEntropy(labelboxKeyBody, 3.5))
	tps = append(tps,
		`LABELBOX_API_KEY=lbx_Ro9deyaHsjRcbQib78WcgTyiW6hkVtLTHcFq67FRSy0`,
		`client = lb.Client(api_key="lbx_Ro9deyaHsjRcbQib78WcgTyiW6hkVtLTHcFq67FRSy0")`,
		`-H "Authorization: Bearer lbx_Ro9deyaHsjRcbQib78WcgTyiW6hkVtLTHcFq67FRSy0"`,
	)
	fps := []string{
		// wrong length
		`LABELBOX_API_KEY=lbx_Ro9deyaHsjRcbQib78WcgTyiW6hkVtLTHcFq67FRSy`,
		`LABELBOX_API_KEY=lbx_Ro9deyaHsjRcbQib78WcgTyiW6hkVtLTHcFq67FRSy0A`,
		// last character has non-zero padding bits
		`LABELBOX_API_KEY=lbx_Ro9deyaHsjRcbQib78WcgTyiW6hkVtLTHcFq67FRSyB`,
		// placeholder
		`LABELBOX_API_KEY=lbx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxw`,
	}
	return utils.Validate(r, tps, fps)
}

// RecursionAPIKey detects Labelbox Recursion (Managed Agents) API keys.
// https://docs.labelbox.com/recursion/api-keys
func RecursionAPIKey() *config.Rule {
	r := config.Rule{
		ID:          "labelbox-recursion-api-key",
		Confidence:  "high",
		Description: "Detected a Labelbox Recursion API key, which acts as its owner to run and manage agents, sessions, and credentials.",
		Regex:       utils.GenerateUniqueTokenRegex(`rma_`+labelboxKeyBody, false),
		Keywords:    []string{"rma_"},
		FilterExpr:  utils.MinEntropy(3.5),
		// Tenant-scoped keys authenticate but get 400 without an x-organization-id header.
		// Unknown, revoked, and expired keys all get 401.
		ValidateExpr: `let r = http.get("https://api.recursion.labelbox.com/managed-agents/v1/models", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 ? {
    "result": "valid"
  } : r.status == 400 && (r.body contains "x-organization-id") ? {
    "result": "valid",
    "reason": "Tenant-scoped API key"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Invalid, revoked, or expired API key"
  } : validate.unknown(r)`,
	}

	tps := utils.GenerateSampleSecrets("recursion", "rma_"+secrets.NewSecretWithEntropy(labelboxKeyBody, 3.5))
	tps = append(tps,
		`export RECURSION_API_KEY='rma_kZfAglqH0NtGp7mHUr1y_n1y4TuCc_6W-oaa2EPkl0I'`,
		`-H "Authorization: Bearer rma_kZfAglqH0NtGp7mHUr1y_n1y4TuCc_6W-oaa2EPkl0I"`,
	)
	fps := []string{
		// documentation placeholder
		`export RECURSION_API_KEY='rma_...'`,
		// wrong length
		`RECURSION_API_KEY=rma_kZfAglqH0NtGp7mHUr1y_n1y4TuCc_6W-oaa2EPkl0`,
		// last character has non-zero padding bits
		`RECURSION_API_KEY=rma_kZfAglqH0NtGp7mHUr1y_n1y4TuCc_6W-oaa2EPkl0h`,
		// inside a longer identifier
		`Xrma_kZfAglqH0NtGp7mHUr1y_n1y4TuCc_6W-oaa2EPkl0I`,
	}
	return utils.Validate(r, tps, fps)
}
