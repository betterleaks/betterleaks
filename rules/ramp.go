package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "ramp-client-id",
	Confidence:  "high",
	Description: "Ramp client ID, used as a component of the Ramp client-secret composite rule.",
	Regex:       Token(`ramp_id_[A-Za-z0-9]{40}`),
	Keywords:    []string{"ramp_id_"},
	SkipReport:  true,
	FilterExpr:  MinEntropy(3.0),
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: "RAMP_CLIENT_ID=ramp_id_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k",
			Expect: []config.ExpectedFinding{
				{Secret: "ramp_id_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  "RAMP_CLIENT_ID=ramp_id_short",
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 2",
			Mode:   "match",
			Input:  "RAMP_CLIENT_ID=ramp_id_0000000000000000000000000000000000000000",
			Expect: []config.ExpectedFinding{},
		},
	},
})

var _ = Add(config.Rule{
	ID:          "ramp-client-secret",
	Confidence:  "high",
	Description: "Ramp OAuth client secret.",
	Regex:       Token(`ramp_sec_[A-Za-z0-9]{48}`),
	Keywords:    []string{"ramp_sec_"},
	Components: []config.Component{
		{RuleID: "ramp-client-id"},
	},
	ValidateExpr: `let r = http.post("https://api.ramp.com/developer/v1/token", {
    "Authorization": "Basic " + base64.encode(bytes((components["ramp-client-id"]?.secret ?? "") + ":" + finding["secret"])),
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json"
  }, "grant_type=client_credentials&scope=betterleaks%3Avalidate"); r.status == 200
    && (r.json?.access_token ?? "") != "" ? {
    "result": "valid"
  } : r.status == 400
    && (r.json?.error ?? "") in ["invalid_scope", "unauthorized_client"] ? {
    "result": "valid"
  } : r.status == 401 && (r.json?.error_v2?.error_code ?? "") == "5001" ? {
    "result": "invalid",
    "reason": "Invalid client credentials"
  } : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "RAMP_CLIENT_SECRET=ramp_sec_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyK\nRAMP_CLIENT_ID=ramp_id_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k",
			Expect: []config.ExpectedFinding{
				{Secret: "ramp_sec_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575klKiz9pyK", ComponentSets: []map[string]string{{"ramp-client-id": "ramp_id_RFbD56TI2smTyVsGd5Xav0yu99ZAMPTA7z7s575k"}}},
			},
		},
		NoMatch("false positive 1", "RAMP_CLIENT_SECRET=ramp_sec_short"),
		NoMatch("false positive 2", "RAMP_CLIENT_SECRET=ramp_sec_000000000000000000000000000000000000000000000000"),
	},
})
