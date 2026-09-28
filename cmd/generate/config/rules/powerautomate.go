package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

// Format of Microosoft Power Automate and Logic Apps webhook URLs.
//
// Power Automate webhook
// https://{environment-id-truncated}.{environment-id-last-2-chars}.environment.api.powerplatform.com:443
//   /powerautomate/automations/direct
//   /cu/{cluster}  # optional
//   /workflows/{workflow-id}
//   /triggers/{trigger-name}
//   /paths/invoke
//   ?api-version=1
//   &sp=%2Ftriggers%2F{trigger-name}%2Frun
//   &sv=1.0
//   &sig={shared-access-signature}
//
// Logic App (Consumption) webhook
// https://{cluster}.{region}.logic.azure.com:443
//   /workflows/{workflow-id}
//   /versions/{version-id}  # sometimes present
//   /triggers/{trigger-name}
//   /paths/invoke
//   ?api-version=2016-10-01
//   &sp=%2Ftriggers%2F{trigger-name}%2Frun
//   &sv=1.0
//   &sig={shared-access-signature}
//
// Logic App (standard) webhook
// https://{logic-app-name}.azurewebsites.net:443/api
//   /{workflow-name}
//   /triggers/{trigger-name}
//   /invoke
//   ?api-version=2022-05-01
//   &sp=%2Ftriggers%2F{trigger-name}%2Frun
//   &sv=1.0
//   &sig={shared-access-signature}

// PowerAutomateWorkflowURL detects Power Automate and Logic Apps webhooks. The
// "sig" query parameter is a SAS signature, so the URL alone is enough to
// trigger the flow or post to a channel; there is no separate secret to extract.
func PowerAutomateWorkflowURL() *config.Rule {
	r := config.Rule{
		ID:          "microsoft-power-automate-workflow-url",
		Confidence:  "high",
		Description: "Identified a Power Automate or Logic Apps workflow invoke URL. The sig query parameter is a SAS signature, so the URL alone can trigger the flow.",
		// sig is base64 (standard or urlsafe alphabet) and may have its +, /,
		// and = percent-encoded. Standard Logic Apps omit the "paths/"
		// segment that Consumption Logic Apps and Power Automate use.
		Regex:      `(?P<url>https://[a-z0-9.\-]+\.(?:logic\.azure\.com|environment\.api\.powerplatform\.com|azurewebsites\.net)(?::443)?/[^\s"'<>]*?/triggers/[A-Za-z0-9_\-]+/(?:paths/)?invoke\?[^\s"'<>]*sig=(?P<sig>(?:[A-Za-z0-9_\-]|%(?:2[BbFf]|3[Dd])){32,}))`,
		ValueGroup: 2,
		Keywords: []string{
			"logic.azure.com",
			"powerplatform.com",
			"azurewebsites.net",
		},
		// No ValidateExpr: Although Power Automate webhooks created for
		// sending messages to Teams are POST-only and have no GET
		// side-effects, other visually-identical Power Automate and Logic Apps
		// webhooks can belong to a trigger that accepts GET, and can return
		// application data or cause side-effects - i.e. unauthorized access we
		// shouldn't do just to validate a finding.
	}

	tps := []string{
		// Power Automate example URL
		"https://default" + secrets.NewSecret(utils.Hex("32")) + ".12.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/06/workflows/" +
			secrets.NewSecret(utils.Hex("32")) +
			"/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=" +
			secrets.NewSecret(`[A-Za-z0-9_\-]{43}`), // betterleaks:allow
		// Logic App (Consumption) example URL
		"https://prod-19.eastus.logic.azure.com:443/workflows/" +
			secrets.NewSecret(utils.Hex("32")) +
			"/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=" +
			secrets.NewSecret(`[A-Za-z0-9_\-]{43}`), // betterleaks:allow
		// Logic App (Consumption) with percent-encoded +, /, and = characters
		"https://prod-19.eastus.logic.azure.com:443/workflows/" +
			secrets.NewSecret(utils.Hex("32")) +
			"/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=" +
			secrets.NewSecret(`[A-Za-z0-9]{20}`) + "%2B" + secrets.NewSecret(`[A-Za-z0-9]{10}`) + "%2F" + secrets.NewSecret(`[A-Za-z0-9]{10}`) + "%3D", // betterleaks:allow
		// Logic App (Standard): single-tenant, no "paths/" segment before invoke
		"https://contoso-integration-app.azurewebsites.net:443/api/ProcessOrderWorkflow/triggers/manual/invoke?api-version=2022-05-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=" +
			secrets.NewSecret(`[A-Za-z0-9_\-]{43}`), // betterleaks:allow
	}
	fps := []string{
		// Documentation placeholders fall below the 32-character floor or use
		// disallowed characters.
		"https://prod-19.eastus.logic.azure.com/workflows/" + secrets.NewSecret(utils.Hex("32")) + "/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=xxxxx",
		"https://prod-19.eastus.logic.azure.com/workflows/" + secrets.NewSecret(utils.Hex("32")) + "/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=<signature>",
		// Not an invoke trigger path.
		"https://prod-19.eastus.logic.azure.com/workflows/" + secrets.NewSecret(utils.Hex("32")) + "/triggers/manual/paths/other?sig=" + secrets.NewSecret(`[A-Za-z0-9_\-]{43}`),
		// Ordinary App Service URL on the same shared domain, not a workflow invoke.
		"https://contoso-integration-app.azurewebsites.net/api/orders/" + secrets.NewSecret(utils.Hex("32")),
	}
	return utils.Validate(r, tps, fps)
}
