package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "clickhouse-cloud-api-secret-key",
	Confidence:  "high",
	Description: "Identified a pattern that may indicate clickhouse cloud API secret key, risking unauthorized clickhouse cloud api access and data breaches on ClickHouse Cloud platforms.",
	Regex:       `\b(4b1d[A-Za-z0-9]{38})\b`,
	Keywords: []string{
		"4b1d", // Prefix
	},
	Components: []config.Component{
		{RuleID: "clickhouse-cloud-key-id"},
	},
	ValidateExpr: `let r = http.get("https://api.clickhouse.cloud/v1/organizations", {
    "Authorization": "Basic " + base64.encode(bytes((components["clickhouse-cloud-key-id"]?.secret ?? "") + ":" + finding["secret"]))
  }); r.status == 200 && (r.body contains "\"id\":") && (r.body contains "\"name\":") ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	FilterExpr: `entropy(finding["secret"]) < 3.5`,
	Tests: []config.RuleTest{
		{
			Name:  "ClickHouse assignment",
			Input: "ClickHouseToken = \"4b1dwEZ8aNo1U9ODBqffSci1INBrltLHM2d1bHF4dq\"\nclickhouse_id = 4ywspD2Tb0gJh4QbLnDI",
			Expect: []config.ExpectedFinding{
				{Secret: "4b1dwEZ8aNo1U9ODBqffSci1INBrltLHM2d1bHF4dq", ComponentSets: []map[string]string{{"clickhouse-cloud-key-id": "4ywspD2Tb0gJh4QbLnDI"}}},
			},
		},
		{
			Name:  "ClickHouse assignment 2",
			Input: "ClickHouseToken = \"4b1dRFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s57\"\nclickhouse_id = 4ywspD2Tb0gJh4QbLnDI",
			Expect: []config.ExpectedFinding{
				{Secret: "4b1dRFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s57", ComponentSets: []map[string]string{{"clickhouse-cloud-key-id": "4ywspD2Tb0gJh4QbLnDI"}}},
			},
		},
		NoMatch("Low entropy", "key = 4b1dXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"),
		NoMatch("Not start of a word", "key = adf4b1dbRdW3rOcB7xLthrM4BTBGK1qPLkHigpN1bXD6z"),
	},
})

var _ = Add(config.Rule{
	ID:          "clickhouse-cloud-key-id",
	Confidence:  "high",
	Description: "Detected a ClickHouse Cloud key ID, used as a component of the clickhouse-cloud-api-secret-key composite rule.",
	Regex:       `(?i)\bclickhouse(?:.|[\n\r]){0,16}?(?:ID|USER)(?:.|[\n\r]){0,16}?([a-z0-9]{20})`,
	Keywords:    []string{"clickhouse"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) < 3.0`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: "clickhouse_id = 4ywspD2Tb0gJh4QbLnDI",
			Expect: []config.ExpectedFinding{
				{Secret: "4ywspD2Tb0gJh4QbLnDI"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  "id = 4ywspD2Tb0gJh4QbLnDI",
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 2",
			Mode:   "match",
			Input:  "clickhouse_id = short",
			Expect: []config.ExpectedFinding{},
		},
	},
})
