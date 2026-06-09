package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func ClickHouseCloud() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "clickhouse-cloud-api-secret-key",
		Description: "Identified a pattern that may indicate clickhouse cloud API secret key, risking unauthorized clickhouse cloud api access and data breaches on ClickHouse Cloud platforms.",
		Regex:       regexp.MustCompile(`\b(4b1d[A-Za-z0-9]{38})\b`),
		Keywords: []string{
			"4b1d", // Prefix
		},
		RequiredRules: []*config.Required{
			{RuleID: "clickhouse-cloud-key-id"},
		},
		ValidateCEL: `cel.bind(r,
  http.get("https://api.clickhouse.cloud/v1/organizations", {
    "Authorization": "Basic " + base64.encode(bytes(captures["clickhouse-cloud-key-id"] + ":" + finding["secret"]))
  }),
  r.status == 200 && r.body.contains("\"id\":") && r.body.contains("\"name\":") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: `filter.entropy(finding["secret"]) < 3.5`,
	}

	// validate
	tps := utils.GenerateSampleSecrets("ClickHouse", "4b1dwEZ8aNo1U9ODBqffSci1INBrltLHM2d1bHF4dq")
	tps = append(tps, utils.GenerateSampleSecrets("ClickHouse", "4b1d"+secrets.NewSecretWithEntropy("[A-Za-z0-9]{38}", 3.5))...)
	fps := []string{
		`key = 4b1dXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,    // Low entropy
		`key = adf4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z`, // Not start of a word
	}
	return utils.Validate(r, tps, fps)
}

func ClickHouseCloudKeyID() *config.Rule {
	r := config.Rule{
		RuleID:      "clickhouse-cloud-key-id",
		Description: "Detected a ClickHouse Cloud key ID, used as a component of the clickhouse-cloud-api-secret-key composite rule.",
		Regex:       regexp.MustCompile(`(?i)\bclickhouse(?:.|[\n\r]){0,16}?(?:ID|USER)(?:.|[\n\r]){0,16}?([a-z0-9]{20})`),
		Keywords:    []string{"clickhouse"},
		SkipReport:  true,
		Filter:      `filter.entropy(finding["secret"]) < 3.0`,
	}

	tps := []string{
		`clickhouse_id = 4ywspD2Tb0gJh4QbLnDI`,
	}
	fps := []string{
		`id = 4ywspD2Tb0gJh4QbLnDI`,
		`clickhouse_id = short`,
	}
	return utils.Validate(r, tps, fps)
}
