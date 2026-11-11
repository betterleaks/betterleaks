package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "cockroachlabs-cloud-api-key",
	Confidence:  "high",
	Description: "Detected a CockroachDB Cloud service account API key, which may allow unauthorized access to CockroachDB Cloud resources.",
	Regex:       `\b(CCDB1_[A-Za-z0-9]{22}_[A-Za-z0-9]{40})\b`,
	Keywords:    []string{"CCDB1_"},
	ValidateExpr: `let r = http.get("https://cockroachlabs.cloud/api/v1/clusters", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  }); r.status == 200 && (r.body contains "\"clusters\"") && (r.body contains "\"pagination\"") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5`,
	Tests: []config.RuleTest{
		Match("bare secret", "CCDB1_z4m5MjGmTx3O4sK2IxvHIh_zv4Cbt3lNujc7f9TO9cZ1qGU7tyJhxrw01I0rWnZ", "CCDB1_z4m5MjGmTx3O4sK2IxvHIh_zv4Cbt3lNujc7f9TO9cZ1qGU7tyJhxrw01I0rWnZ"),
		Match("bare secret 2", "CCDB1_z6ju5QJ1vZf1SGhBr2yM97_vqqya4b8lKf2ZRfI3OFHZ478xfi6SbqcIbts4nyp", "CCDB1_z6ju5QJ1vZf1SGhBr2yM97_vqqya4b8lKf2ZRfI3OFHZ478xfi6SbqcIbts4nyp"),
		Match("bare secret 3", "CCDB1_OMxzun9l3g5vjIJRqKqPP7_9HUwzxJDBGpEvtbN3HjJb7L7zirVo3qSCAi1MCct", "CCDB1_OMxzun9l3g5vjIJRqKqPP7_9HUwzxJDBGpEvtbN3HjJb7L7zirVo3qSCAi1MCct"),
		NoMatch("false positive 1", "CCDB1_short_9HUwzxJDBGpEvtbN3HjJb7L7zirVo3qSCAi1MCct"),
	},
})
