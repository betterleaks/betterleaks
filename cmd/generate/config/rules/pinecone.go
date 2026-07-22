package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

const pineconeValidateExpr = `let r = http.get("https://api.pinecone.io/indexes", {
    "Api-Key": finding["secret"],
    "X-Pinecone-Api-Version": "2025-10",
    "Accept": "application/json"
  }); r.status == 200 && r.json?.indexes != null ? {
    "result": "valid"
  } : r.status == 403 ? {
    "result": "valid",
    "reason": "Authenticated but control-plane access is restricted"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`

func PineconeAPIKeyV1() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "pinecone-api-key.1",
		Description: "Pinecone API key version 1 (UUID format).",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`pinecone(?:[_. -]*(?:api))?[_. -]*(?:secret|key|token)`},
			`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
			false,
		),
		Keywords:     []string{"pinecone"},
		ValidateExpr: pineconeValidateExpr,
		Filter:       utils.MinEntropy(3.0),
	}

	// validate
	tps := []string{
		`PINECONE_API_KEY=62b0dbfe-3489-4b79-b850-34d911527c88`,
	}
	fps := []string{
		`DATABASE_ID=62b0dbfe-3489-4b79-b850-34d911527c88`,
		`PINECONE_API_KEY=00000000-0000-0000-0000-000000000000`,
	}
	return utils.Validate(r, tps, fps)
}

func PineconeAPIKeyV2() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:       "pinecone-api-key.2",
		Description:  "Pinecone API key version 2 (pcsk format).",
		Regex:        utils.GenerateUniqueTokenRegex(`pcsk_[A-Za-z0-9]{5,6}_[A-Za-z0-9]{63}`, false),
		Keywords:     []string{"pcsk_"},
		ValidateExpr: pineconeValidateExpr,
		Filter:       utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"PINECONE_API_KEY=pcsk_" + secrets.NewSecret(`[A-Za-z0-9]{6}`) + "_" + secrets.NewSecretWithEntropy(`[A-Za-z0-9]{63}`, 3.5),
	}
	fps := []string{
		`PINECONE_API_KEY=pcsk_short`,
		`PINECONE_API_KEY=pcsk_abc12_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}
	return utils.Validate(r, tps, fps)
}
