package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

func FastmailAPIToken() *config.Rule {
	// fmu1-<8 hex>-<32 hex>-<digit>-<32 hex>; JMAP and MCP tokens share the format but only authenticate on their own endpoint
	r := config.Rule{
		Description: "Discovered a Fastmail API token, risking unauthorized access to email, contacts, and calendars.",
		ID:          "fastmail-api-token",
		Confidence:  "high",
		Regex:       utils.GenerateUniqueTokenRegex(`fmu1-[a-f0-9]{8}-[a-f0-9]{32}-\d-[a-f0-9]{32}`, false),
		Keywords:    []string{"fmu1-"},
		ValidateExpr: `let jmap = http.get("https://api.fastmail.com/jmap/session", {
    "Authorization": "Bearer " + finding["secret"],
    "Accept": "application/json"
  });
jmap.status == 200 ? {
    "result": "valid"
  } : jmap.status in [401, 403] ? (
    let mcp = http.post("https://api.fastmail.com/mcp", {
        "Authorization": "Bearer " + finding["secret"],
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream"
      }, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"betterleaks\",\"version\":\"0\"}}}");
    mcp.status == 200 ? {
        "result": "valid"
      } : mcp.status in [401, 403] ? {
        "result": "invalid",
        "reason": "Unauthorized"
      } : validate.unknown(mcp)
  ) : validate.unknown(jmap)`,
	}

	tps := []string{
		`FASTMAIL_API_TOKEN=fmu1-` + secrets.NewSecret(utils.Hex("8")) + `-` + secrets.NewSecret(utils.Hex("32")) + `-0-` + secrets.NewSecret(utils.Hex("32")),
		`"Authorization": "Bearer fmu1-` + secrets.NewSecret(utils.Hex("8")) + `-` + secrets.NewSecret(utils.Hex("32")) + `-0-` + secrets.NewSecret(utils.Hex("32")) + `"`,
	}

	fps := []string{
		`fmu1-` + secrets.NewSecret(utils.Hex("8")) + `-` + secrets.NewSecret(utils.Hex("8")),
		`fmu1-config-name = "staging"`,
	}

	return utils.Validate(r, tps, fps)
}
