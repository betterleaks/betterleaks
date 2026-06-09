package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func CockroachLabsCloudAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "cockroachlabs-cloud-api-key",
		Description: "Detected a CockroachDB Cloud service account API key, which may allow unauthorized access to CockroachDB Cloud resources.",
		Regex:       regexp.MustCompile(`\b(CCDB1_[A-Za-z0-9]{22}_[A-Za-z0-9]{40})\b`),
		Keywords:    []string{"CCDB1_"},
		ValidateCEL: `cel.bind(r,
  http.get("https://cockroachlabs.cloud/api/v1/clusters", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }),
  r.status == 200 && r.body.contains("\"clusters\"") && r.body.contains("\"pagination\"") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: `filter.entropy(finding["secret"]) < 3.5`,
	}

	tps := []string{
		`CCDB1_z4m5MjGmTx3O4sK2IxvHIh_zv4Cbt3lNujc7f9TO9cZ1qGU7tyJhxrw01I0rWnZ`,
		`CCDB1_z6ju5QJ1vZf1SGhBr2yM97_vqqya4b8lKf2ZRfI3OFHZ478xfi6SbqcIbts4nyp`,
		`CCDB1_OMxzun9l3g5vjIJRqKqPP7_9HUwzxJDBGpEvtbN3HjJb7L7zirVo3qSCAi1MCct`,
	}
	fps := []string{
		`CCDB1_short_9HUwzxJDBGpEvtbN3HjJb7L7zirVo3qSCAi1MCct`,
	}
	return utils.Validate(r, tps, fps)
}
