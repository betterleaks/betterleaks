package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

// https://blog.postman.com/accessing-information-about-the-postman-api-authenticated-user/
const postmanValidateExpr = `let r = http.get("https://api.getpostman.com/me", {
  "X-Api-Key": finding["secret"], "Accept": "application/json"
});
let body = type(r.json) == "map" ? r.json : {};
let user = type(body?.user) == "map" ? body.user : {};
let userID = type(user?.id) == "string" ? user?.id : type(user?.id) == "float" ? string(int(user?.id)) : "";
r.status == 200 && (userID != "") ? {
  "result": "valid", "analysis": {
    "id": userID,
    "username": type(user?.username) == "string" ? user?.username : "",
    "name": type(user?.fullName) == "string" ? user?.fullName : "",
    "email": type(user?.email) == "string" ? user?.email : ""
  }
} : r.status == 401 ? {"result": "invalid", "reason": "Unauthorized"} : validate.unknown(r)`
const postmanAnalyzeExpr = `let input = validation.analysis;
{
  "identity": {
    "id": input["id"] ?? "",
    "username": input["username"] ?? "",
    "name": input["name"] ?? "",
    "email": input["email"] ?? ""
  },
  "capabilities": []
}`

var _ = rulebuilder.Add(config.Rule{
	ID:          "postman-api-token",
	Confidence:  "high",
	Description: "Uncovered a Postman API token, potentially compromising API testing and development workflows.",
	Regex:       rulebuilder.Token(`PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34}`),
	Keywords: []string{
		"pmak-",
	},
	FilterExpr:   `entropy(finding["secret"]) <= 3.0`,
	ValidateExpr: postmanValidateExpr,
	AnalyzeExpr:  postmanAnalyzeExpr,
	Tests: []config.RuleTest{
		rulebuilder.Match("assignment", `postmanAPItokenToken = "PMAK-1f7b169c846f218ab552fa82-1f7b169c846f218ab552fa82fbf86758bf"`, "PMAK-1f7b169c846f218ab552fa82-1f7b169c846f218ab552fa82fbf86758bf"),
	},
})
