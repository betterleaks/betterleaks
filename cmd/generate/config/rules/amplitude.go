package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func AmplitudeSecretKey() *config.Rule {
	r := config.Rule{
		RuleID:      "amplitude-secret-key",
		Description: "Detected an Amplitude secret key, which may allow unauthorized event ingestion or access to Amplitude API functionality.",
		Regex:       regexp.MustCompile(`(?i)\bamplitude(?:.|[\n\r]){0,32}?(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN|AUTHORIZATION)(?:.|[\n\r]){0,16}?\b([a-f0-9]{32})\b`),
		Keywords:    []string{"amplitude"},
		ValidateCEL: `cel.bind(r,
  http.post("https://api2.amplitude.com/2/httpapi", {
    "Content-Type": "application/json",
    "Accept": "*/*"
  },
  "{" +
    "\"api_key\":" + json.string(finding["secret"]) + "," +
    "\"events\":[{" +
      "\"user_id\":\"203201202\"," +
      "\"device_id\":\"C8F9E604-F01A-4BD9-95C6-8E5357DF265D\"," +
      "\"event_type\":\"watch_tutorial\"" +
    "}]" +
  "}"),
  r.status == 200 && r.body.contains("\"code\":200") ? {
    "result": "valid"
  } : r.status in [400, 401, 403] ? {
    "result": "invalid",
    "reason": r.json.?error.orValue("Unauthorized")
  } : validate.unknown(r)
)`,
		Filter: `filter.entropy(finding["secret"]) < 3.3`,
	}

	tps := []string{
		`amplitude_api_key=8b6f8d6594749cb659b1be03e6a0a2e7`,
		`AMPLITUDE_API_KEY=ef929907c3923e8f3da83c24f0255aa6`,
		`AMPLITUDE_SECRET_KEY=8b6f8d6594749cb659b1be03e6a0a2e7`,
	}
	fps := []string{
		`api_key=8b6f8d6594749cb659b1be03e6a0a2e7`,
		`AMPLITUDE_SECRET_KEY=8b6f8d6594749cb659b1be03e6a0a2e`,
	}
	return utils.Validate(r, tps, fps)
}
