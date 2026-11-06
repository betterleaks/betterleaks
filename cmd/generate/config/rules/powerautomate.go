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
		// sig is base64 (standard or urlsafe alphabet); its +, /, and = may
		// appear literally or percent-encoded. Standard Logic Apps omit the
		// "paths/" segment that Consumption Logic Apps and Power Automate use.
		Regex: `(?P<url>https://(?i:[a-z0-9.\-]+\.` +
			`(?:logic\.azure\.com|environment\.api\.powerplatform\.com|azurewebsites\.net))` +
			`(?::443)?/[^\s"'<>]*?/triggers/[A-Za-z0-9_\-]+/(?:paths/)?invoke\?` +
			`[^\s"'<>]*sig=(?P<sig>(?:[A-Za-z0-9_+/=\-]|%(?:2[BbFf]|3[Dd])){32,}))`,
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
		//
		// Skip Microsoft's own documentation placeholders: the workflow id
		// c4ed9335bc864140a11f4508d19acea3, and environment ids
		// aaaabbbb-0000-cccc-1111-dddd2222eeee and aaaa0000-bb11-2222-33cc-444444dddddd
		// (dashes are omitted, and split into truncated+last-2-chars, in the URL).
		FilterExpr: `let url = lower(finding["captures"]?.url ?? "");
url contains "/workflows/c4ed9335bc864140a11f4508d19acea3" ||
url contains "aaaabbbb0000cccc1111dddd2222ee.ee.environment.api.powerplatform.com" ||
url contains "aaaa0000bb11222233cc444444dddd.dd.environment.api.powerplatform.com"`,
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
		// Logic App (Consumption) with literal, unescaped +, /, and = characters
		"https://prod-19.eastus.logic.azure.com:443/workflows/" +
			secrets.NewSecret(utils.Hex("32")) +
			"/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=" +
			secrets.NewSecret(`[A-Za-z0-9]{20}`) + "+" + secrets.NewSecret(`[A-Za-z0-9]{10}`) + "/" + secrets.NewSecret(`[A-Za-z0-9]{10}`) + "=", // betterleaks:allow
		// Logic App (Standard): single-tenant, no "paths/" segment before invoke
		"https://contoso-integration-app.azurewebsites.net:443/api/ProcessOrderWorkflow/triggers/manual/invoke?api-version=2022-05-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=" +
			secrets.NewSecret(`[A-Za-z0-9_\-]{43}`), // betterleaks:allow
		// Mixed-case hostname: DNS is case-insensitive, so this must still match.
		"https://Prod-19.EastUS.Logic.Azure.Com:443/workflows/" +
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
		// Ordinary App Service URL on the same shared domain, not a workflow invoke.
		"https://contoso-integration-app.azurewebsites.net/api/orders/" + secrets.NewSecret(utils.Hex("32")),
		// Microsoft's documentation placeholder workflow id.
		"https://prod-19.eastus.logic.azure.com:443/workflows/c4ed9335bc864140a11f4508d19acea3/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=" +
			secrets.NewSecret(`[A-Za-z0-9_\-]{43}`), // betterleaks:allow
		// Microsoft's documentation placeholder environment id, "default"-prefixed.
		"https://defaultaaaabbbb0000cccc1111dddd2222ee.ee.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/06/workflows/" +
			secrets.NewSecret(utils.Hex("32")) +
			"/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=" +
			secrets.NewSecret(`[A-Za-z0-9_\-]{43}`), // betterleaks:allow
		// Microsoft's other documentation placeholder environment id.
		"https://aaaa0000bb11222233cc444444dddd.dd.environment.api.powerplatform.com:443/powerautomate/automations/direct/cu/06/workflows/" +
			secrets.NewSecret(utils.Hex("32")) +
			"/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=" +
			secrets.NewSecret(`[A-Za-z0-9_\-]{43}`), // betterleaks:allow
	}
	return utils.Validate(r, tps, fps)
}
