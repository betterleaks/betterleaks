package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "virustotal-api-key.1",
	Confidence:  "high",
	Description: "VirusTotal API key, which may expose private submissions, intelligence, or account API access.",
	Regex:       Assignment([]string{"virustotal"}, `(?i)`+Hex("64")),
	Keywords:    []string{"virustotal"},
	ValidateExpr: `let r = http.get("https://www.virustotal.com/api/v3/domains/google.com", {
    "x-apikey": finding["secret"],
    "Accept": "application/json"
  }); let errorCode = (r.json?.error?.code ?? "");
r.status == 200 && (r.body contains "\"data\"") ? {
  "result": "valid"
} : r.status == 403 && errorCode == "ForbiddenError" ? {
  "result": "valid",
  "reason": "Authenticated but operation is forbidden"
} : r.status == 401 && errorCode == "UserNotActiveError" ? {
  "result": "valid",
  "reason": "Authenticated inactive VirusTotal account"
} : r.status == 401 && errorCode == "WrongCredentialsError" ? {
  "result": "invalid",
  "reason": "Wrong credentials"
} : validate.unknown(r)`,
	FilterExpr: MinEntropy(3.5),
	Tests: []config.RuleTest{
		Match("true positive 1", "VIRUSTOTAL_API_KEY=1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc", "1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc"),
		Match("true positive 2", `virustotal x-apikey: "1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc"`, "1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc"),
		NoMatch("false positive 1", "API_KEY=1f7b169c846f218ab552fa82fbf86758bf5c97d2d2a313e4f95957818a7b3edc"),
		NoMatch("false positive 2", "VIRUSTOTAL_API_KEY=short"),
		NoMatch("false positive 3", "VIRUSTOTAL_API_KEY=0000000000000000000000000000000000000000000000000000000000000000"),
	},
})
