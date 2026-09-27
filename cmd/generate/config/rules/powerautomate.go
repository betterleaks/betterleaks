package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

// PowerAutomateWorkflowURL detects Power Automate and Logic Apps workflow
// invoke URLs. The "sig" query parameter is a SAS signature, so the URL alone
// is enough to trigger the flow or post to a channel; there is no separate
// secret to extract.
func PowerAutomateWorkflowURL() *config.Rule {
	r := config.Rule{
		ID:          "microsoft-power-automate-workflow-url",
		Confidence:  "high",
		Description: "Identified a Power Automate or Logic Apps workflow invoke URL. The sig query parameter is a SAS signature, so the URL alone can trigger the flow.",
		Regex:       `(?P<url>https://[a-z0-9.\-]+\.(?:logic\.azure\.com|environment\.api\.powerplatform\.com)(?::443)?/[^\s"'<>]*?/triggers/[A-Za-z0-9_\-]+/paths/invoke\?[^\s"'<>]*sig=(?P<sig>[A-Za-z0-9_\-]{32,}))`,
		ValueGroup:  2,
		Keywords: []string{
			"logic.azure.com",
			"powerplatform.com",
			"paths/invoke",
		},
		// A GET request never triggers the flow: Power Automate and Logic Apps
		// invoke triggers require POST and reject GET with 400 before running.
		// A disabled trigger reuses the same error code as a deleted one, so
		// the reason is split on the state name: disabling is reversible and
		// the URL stays a live risk, unlike a deleted workflow.
		ValidateExpr: `let r = http.get(finding["captures"]["url"], {"User-Agent": "betterleaks"});
let code = r.json?.error?.code ?? "";
r.status == 200 ? {
    "result": "valid"
  } : code == "TriggerRequestMethodNotValid" ? {
    "result": "valid"
  } : code == "WorkflowTriggerIsNotEnabled" && (r.body contains "state 'Deleted'") ? {
    "result": "invalid",
    "reason": "Workflow deleted"
  } : code == "WorkflowTriggerIsNotEnabled" ? {
    "result": "invalid",
    "reason": "Workflow disabled; can be re-enabled without changing the signature"
  } : r.status in [401, 404] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)`,
	}

	tps := []string{
		"https://default" + secrets.NewSecret(utils.Hex("32")) + ".12.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/06/workflows/" +
			secrets.NewSecret(utils.Hex("32")) +
			"/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=" +
			secrets.NewSecret(`[A-Za-z0-9_\-]{43}`), // betterleaks:allow
		"https://prod-19.eastus.logic.azure.com:443/workflows/" +
			secrets.NewSecret(utils.Hex("32")) +
			"/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=" +
			secrets.NewSecret(`[A-Za-z0-9_\-]{43}`), // betterleaks:allow
	}
	fps := []string{
		// Documentation placeholders fall below the 32-character floor or use
		// disallowed characters.
		"https://prod-19.eastus.logic.azure.com/workflows/" + secrets.NewSecret(utils.Hex("32")) + "/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=xxxxx",
		"https://prod-19.eastus.logic.azure.com/workflows/" + secrets.NewSecret(utils.Hex("32")) + "/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=<signature>",
		// Not an invoke trigger path.
		"https://prod-19.eastus.logic.azure.com/workflows/" + secrets.NewSecret(utils.Hex("32")) + "/triggers/manual/paths/other?sig=" + secrets.NewSecret(`[A-Za-z0-9_\-]{43}`),
	}
	return utils.Validate(r, tps, fps)
}
