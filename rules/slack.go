package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
)

const slackValidateExpr = `let r = http.post("https://slack.com/api/auth.test", {
  "Authorization": "Bearer " + finding["secret"],
  "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"
}, "");
let provider_error = r.json?.error ?? "";
r.status == 200 && (r.json?.ok ?? false) ? {
  "result": "valid",
  "analysis": {
    "team_id": (r.json?.team_id ?? ""),
    "team": (r.json?.team ?? ""),
    "enterprise_id": (r.json?.enterprise_id ?? ""),
    "user_id": (r.json?.user_id ?? ""),
    "user": (r.json?.user ?? ""),
    "bot_id": (r.json?.bot_id ?? ""),
    "scopes": strings.splitTrim((r.headers["x-oauth-scopes"] ?? ""), ",")
  }
} : provider_error in ["token_revoked", "token_expired", "account_inactive"] ? {
  "result": "revoked",
  "reason": provider_error
} : provider_error in ["invalid_auth", "not_authed"] || r.status in [401, 403] ? {
  "result": "invalid",
  "reason": provider_error == "" ? "Unauthorized" : provider_error
} : {
  "result": "unknown",
  "reason": provider_error == "" ? "Unexpected provider response" : provider_error
}`

const slackAnalyzeExpr = `let input = validation.analysis;
let scopes = input["scopes"] ?? [];
{
  "reason": len(scopes) == 0 ? "Slack did not return OAuth scope metadata" : "",
  "metadata": {
    "enterprise_id": input["enterprise_id"] ?? "",
    "scopes": scopes
  },
  "identity": {
    "id": input["user_id"] ?? input["bot_id"] ?? "",
    "username": input["user"] ?? "",
    "account": {
      "id": input["team_id"] ?? "",
      "name": input["team"] ?? ""
    }
  },
  "capabilities": analysis.capabilities({
    "read": matchesAny(scopes, [":(?:history|read)$"]),
    "write": matchesAny(scopes, [":write$", "^channels:manage$"]),
    "manage_users": matchesAny(scopes, ["^(?:admin[.](?:invites|roles|usergroups|users):write|usergroups:write)$"])
  })
}`

// https://docs.slack.dev/reference/methods/auth.revoke/
const slackRevokeExpr = `let r = http.post("https://slack.com/api/auth.revoke", {
  "Authorization": "Bearer " + finding["secret"],
  "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"
}, "");
r.status == 200 && r.json?.ok == true && r.json?.revoked == true ? {
  "result": "revoked"
} : r.status != 200 ? revoke.unknown(r) : {
  "result": "unknown",
  "reason": "Slack did not confirm revocation",
  "metadata": {"provider_error": r.json?.error ?? ""}
}`

// https://api.slack.com/authentication/token-types#bot
var _ = Add(config.Rule{
	ID:          "slack-bot-token",
	Confidence:  "high",
	Description: "Identified a Slack Bot token, which may compromise bot integrations and communication channel security.",
	Regex:       `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`,
	Keywords: []string{
		"xoxb",
	},
	ValidateExpr: slackValidateExpr,
	AnalyzeExpr:  slackAnalyzeExpr,
	RevokeExpr:   slackRevokeExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		Match("bot assignment", `botToken = "xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD"`, "xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD"),
		Match("true positive 1", `"bot_token1": "xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD"`, "xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD"),
		Match("true positive 2", `"bot_token2": "xoxb-263594206564-2343594206574-FGqddMF8t08v8N7Oq4i57vs1MBS"`, "xoxb-263594206564-2343594206574-FGqddMF8t08v8N7Oq4i57vs1MBS"),
		Match("true positive 3", `"bot_token3": "xoxb-4614724432022-5152386766518-O5WzjWGLG0wcCm2WPrjEmnys"`, "xoxb-4614724432022-5152386766518-O5WzjWGLG0wcCm2WPrjEmnys"),
		Match("true positive 4", `"bot_token4": xoxb-1779185060-41298415768`, "xoxb-1779185060-41298415768"),
		NoMatch("false positive 1", "xoxb-xxxxxxxxx-xxxxxxxxxx-xxxxxxxxxxxx"),
		NoMatch("false positive 2", "xoxb-xxx"),
		NoMatch("false positive 3", "xoxb-12345-abcd234"),
		NoMatch("false positive 4", "xoxb-xoxb-my-bot-token"),
	},
})

// https://api.slack.com/authentication/token-types#user
var _ = Add(config.Rule{
	ID:          "slack-user-token",
	Confidence:  "high",
	Description: "Found a Slack User token, posing a risk of unauthorized user impersonation and data access within Slack workspaces.",
	// The last segment seems to be consistently 32 characters. I've made it 28-34 just in case.
	Regex:        `xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}`,
	Keywords:     []string{"xoxp-", "xoxe-"},
	ValidateExpr: slackValidateExpr,
	AnalyzeExpr:  slackAnalyzeExpr,
	RevokeExpr:   slackRevokeExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		Match("user assignment", `userToken = "xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef"`, "xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef"),
		Match("true positive 1", `"user_token1": "xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef"`, "xoxp-41684372915-1320496754-45609968301-e708ba56e1517a99f6b5fb07349476ef"),
		Match("true positive 2", `"user_token2": "xoxp-283316862324-298911817009-298923149681-44f585044dace54f5701618e97cd1c0b"`, "xoxp-283316862324-298911817009-298923149681-44f585044dace54f5701618e97cd1c0b"),
		Match("true positive 3", `"user_token3": "xoxp-11873098179-111402824422-234336993777-b96c9fb3b69f82ebb79d12f280779de1"`, "xoxp-11873098179-111402824422-234336993777-b96c9fb3b69f82ebb79d12f280779de1"),
		Match("true positive 4", `"user_token4": "xoxp-254112160503-252950188691-252375361712-6cbf56aada30951a9d310a5f23d032a0"`, "xoxp-254112160503-252950188691-252375361712-6cbf56aada30951a9d310a5f23d032a0"),
		Match("true positive 5", `"user_token5": "xoxp-4614724432022-4621207627011-5182682871568-1ddad9823e8528ad0f4944dfa3c6fc6c"`, "xoxp-4614724432022-4621207627011-5182682871568-1ddad9823e8528ad0f4944dfa3c6fc6c"),
		Match("true positive 6", `"user_token6": xoxp-7791850604-1298415765-6887778051-NeV2zf6BHXUs-sZgjscQ6rfLOh2y`, "xoxp-7791850604-1298415765-6887778051-NeV2zf6BHXUs-sZgjscQ6rfLOh2y"),
		Match("true positive 7", `"url_private": "https:\/\/files.slack.com\/files-pri\/T04MCQMEXQ9-F04MAA1PKE3\/image.png?t=xoxe-4726837507825-4848681849303-4856614048758-e0b1f3d4cb371f92260edb0d9444d206"`, "xoxe-4726837507825-4848681849303-4856614048758-e0b1f3d4cb371f92260edb0d9444d206"),
		NoMatch("false positive 1", "https://docs.google.com/document/d/1W7KCxOxP-1Fy5EyF2lbJGE2WuKmu5v0suYqoHas1jRM"),
		NoMatch("false positive 2", `"token1": "xoxp-1234567890"`),
		NoMatch("false positive 3", `"token2": "xoxp-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"`),
		NoMatch("false positive 4", `"token3": "xoxp-1234-1234-1234-4ddbc191d40ee098cbaae6f3523ada2d"`),
		NoMatch("false positive 5", `"token4": "xoxp-572370529330-573807301142-572331691188-####################"`),
	},
})

// Reference: https://api.slack.com/authentication/token-types#app
var _ = Add(config.Rule{
	ID:          "slack-app-token",
	Confidence:  "high",
	Description: "Detected a Slack App-level token, risking unauthorized access to Slack applications and workspace data.",
	// This regex is based on a limited number of examples and may not be 100% accurate.
	Regex:      `(?i)xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+`,
	Keywords:   []string{"xapp"},
	FilterExpr: `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		Match("slack assignment", `slackToken = "xapp-1-A052FGTS2DL-5171572773297-610b6a11f4b7eb819e87b767d80e6575a3634791acb9a9ead051da879eb5b55e"`, "xapp-1-A052FGTS2DL-5171572773297-610b6a11f4b7eb819e87b767d80e6575a3634791acb9a9ead051da879eb5b55e"),
		Match("true positive 1", `"token1": "xapp-1-A052FGTS2DL-5171572773297-610b6a11f4b7eb819e87b767d80e6575a3634791acb9a9ead051da879eb5b55e"`, "xapp-1-A052FGTS2DL-5171572773297-610b6a11f4b7eb819e87b767d80e6575a3634791acb9a9ead051da879eb5b55e"),
		Match("true positive 2", `"token2": "xapp-1-IEMF8IMY1OQ-4037076220459-85c370b433e366de369c4ef5abdf41253519266982439a75af74a3d68d543fb6"`, "xapp-1-IEMF8IMY1OQ-4037076220459-85c370b433e366de369c4ef5abdf41253519266982439a75af74a3d68d543fb6"),
		Match("true positive 3", `"token3": "xapp-1-BM3V7LC51DA-1441525068281-86641a2582cd0903402ab523e5bcc53b8253098c31591e529b55b41974d2e82f"`, "xapp-1-BM3V7LC51DA-1441525068281-86641a2582cd0903402ab523e5bcc53b8253098c31591e529b55b41974d2e82f"),
	},
})

// Reference: https://api.slack.com/authentication/config-tokens
var _ = Add(config.Rule{
	ID:          "slack-config-access-token",
	Confidence:  "high",
	Description: "Found a Slack Configuration access token, posing a risk to workspace configuration and sensitive data access.",
	Regex:       `(?i)xoxe.xox[bp]-\d-[A-Z0-9]{163,166}`,
	Keywords:    []string{"xoxe.xoxb-", "xoxe.xoxp-"},
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		Match("access assignment", `accessToken = "xoxe.xoxp-1-Mi0yLTM0MTQwNDE0MDE3Ni0zNjU5NDY0Njg4MTctNTE4MjA3NTQ5NjA4MC01NDEyOTYyODY5NzUxLThhMTBjZmI1ZWIzMGIwNTg0ZDdmMDI5Y2UxNzVlZWVhYzU2ZWQyZTZiODNjNDZiMGUxMzRlNmNjNDEwYmQxMjQ"`, "xoxe.xoxp-1-Mi0yLTM0MTQwNDE0MDE3Ni0zNjU5NDY0Njg4MTctNTE4MjA3NTQ5NjA4MC01NDEyOTYyODY5NzUxLThhMTBjZmI1ZWIzMGIwNTg0ZDdmMDI5Y2UxNzVlZWVhYzU2ZWQyZTZiODNjNDZiMGUxMzRlNmNjNDEwYmQxMjQ"),
		Match("true positive 1", `"access_token1": "xoxe.xoxp-1-Mi0yLTM0MTQwNDE0MDE3Ni0zNjU5NDY0Njg4MTctNTE4MjA3NTQ5NjA4MC01NDEyOTYyODY5NzUxLThhMTBjZmI1ZWIzMGIwNTg0ZDdmMDI5Y2UxNzVlZWVhYzU2ZWQyZTZiODNjNDZiMGUxMzRlNmNjNDEwYmQxMjQ"`, "xoxe.xoxp-1-Mi0yLTM0MTQwNDE0MDE3Ni0zNjU5NDY0Njg4MTctNTE4MjA3NTQ5NjA4MC01NDEyOTYyODY5NzUxLThhMTBjZmI1ZWIzMGIwNTg0ZDdmMDI5Y2UxNzVlZWVhYzU2ZWQyZTZiODNjNDZiMGUxMzRlNmNjNDEwYmQxMjQ"),
		Match("true positive 2", `"access_token2": "xoxe.xoxp-1-Mi0yLTMxNzcwMjQ0MTcxMy0zNjU5NDY0Njg4MTctNTE1ODE1MjY5MTcxNC01MTU4MDI0MTgyOTc5LWRmY2YwY2U4ODhhNzY5ZGU5MTAyNDU4MDJjMGQ0ZDliMTZhMjNkMmEyYzliNjkzMDRlN2VjZTI4MWNiMzRkNGQ"`, "xoxe.xoxp-1-Mi0yLTMxNzcwMjQ0MTcxMy0zNjU5NDY0Njg4MTctNTE1ODE1MjY5MTcxNC01MTU4MDI0MTgyOTc5LWRmY2YwY2U4ODhhNzY5ZGU5MTAyNDU4MDJjMGQ0ZDliMTZhMjNkMmEyYzliNjkzMDRlN2VjZTI4MWNiMzRkNGQ"),
		Match("true positive 3", `"access_token4": "xoxe.xoxb-1-Mi0yLTMxNzcwMjQ0MTcxMy0zNjU5NDY0Njg4MTctNTE1ODE1MjY5MTcxNC01MTU4MDI0MTgyOTc5LWRmY2YwY2U4ODhhNzY5ZGU5MTAyNDU4MDJjMGQ0ZDliMTZhMjNkMmEyYzliNjkzMDRlN2VjZTI4MWNiMzRkNGQ"`, "xoxe.xoxb-1-Mi0yLTMxNzcwMjQ0MTcxMy0zNjU5NDY0Njg4MTctNTE1ODE1MjY5MTcxNC01MTU4MDI0MTgyOTc5LWRmY2YwY2U4ODhhNzY5ZGU5MTAyNDU4MDJjMGQ0ZDliMTZhMjNkMmEyYzliNjkzMDRlN2VjZTI4MWNiMzRkNGQ"),
		NoMatch("false positive 1", "xoxe.xoxp-1-SlackAppConfigurationAccessTokenHere"),
		NoMatch("false positive 2", "xoxe.xoxp-1-RANDOMSTRINGHERE"),
		NoMatch("false positive 3", "xoxe.xoxp-1-initial"),
	},
})

// Reference: https://api.slack.com/authentication/config-tokens
var _ = Add(config.Rule{
	ID:          "slack-config-refresh-token",
	Confidence:  "high",
	Description: "Discovered a Slack Configuration refresh token, potentially allowing prolonged unauthorized access to configuration settings.",
	Regex:       `(?i)xoxe-\d-[A-Z0-9]{146}`,
	Keywords:    []string{"xoxe-"},
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		Match("refresh assignment", `refreshToken = "xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg"`, "xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg"),
		Match("true positive 1", `"refresh_token1": "xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg"`, "xoxe-1-My0xLTMxNzcwMjQ0MTcxMy01MTU4MTUyNjkxNzE0LTUxODE4NDI0MDY3MzYtMjA5MGFkOTFlZThkZWE2OGFlZDYwYWJjODNhYzAxYjA5ZjVmODBhYjgzN2QyNDdjOTNlOGY5NTg2YWM1OGM4Mg"),
		Match("true positive 2", `"refresh_token2": "xoxe-1-My0xLTM0MTQwNDE0MDE3Ni01MTgyMDc1NDk2MDgwLTU0MjQ1NjIwNzgxODEtNGJkYTZhYTUxY2M1ODk3ZTNkN2YzMTgxMDI1ZDQzNzgwNWY4NWQ0ODdhZGIzM2ViOGI0MTM0MjdlNGVmYzQ4Ng"`, "xoxe-1-My0xLTM0MTQwNDE0MDE3Ni01MTgyMDc1NDk2MDgwLTU0MjQ1NjIwNzgxODEtNGJkYTZhYTUxY2M1ODk3ZTNkN2YzMTgxMDI1ZDQzNzgwNWY4NWQ0ODdhZGIzM2ViOGI0MTM0MjdlNGVmYzQ4Ng"),
		Match("true positive 3", `"refresh_token3": "xoxe-1-5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lca8hqn2j0qefi1vg8f9p1t7tnza246j0vcrp2lv3hn2adus61vq0dnd3i2a93m65mv90fpqrp820foz4g8n"`, "xoxe-1-5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1rysjl9p9f4p8u7nz6lca8hqn2j0qefi1vg8f9p1t7tnza246j0vcrp2lv3hn2adus61vq0dnd3i2a93m65mv90fpqrp820foz4g8n"),
		NoMatch("false positive 1", "xoxe-1-xxx"),
		NoMatch("false positive 2", "XOxE-RROAmw, Home and Garden, 5:24, 20120323"),
	},
})

// Reference: https://api.slack.com/authentication/token-types#legacy_bot
var _ = Add(config.Rule{
	ID:          "slack-legacy-bot-token",
	Confidence:  "high",
	Description: "Uncovered a Slack Legacy bot token, which could lead to compromised legacy bot operations and data exposure.",
	// This rule is based off the limited information I could find and may not be 100% accurate.
	Regex: `xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}`,
	Keywords: []string{
		"xoxb",
	},
	ValidateExpr: slackValidateExpr,
	AnalyzeExpr:  slackAnalyzeExpr,
	FilterExpr:   `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		Match("slack assignment", `slackToken = "xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1"`, "xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1"),
		Match("true positive 1", `"bot_token1": "xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1"`, "xoxb-263594206564-FGqddMF8t08v8N7Oq4i57vs1"),
		Match("true positive 2", `"bot_token2": "xoxb-282029623751-BVtmnS3BQitmjZvjpQL7PSGP"`, "xoxb-282029623751-BVtmnS3BQitmjZvjpQL7PSGP"),
		Match("true positive 3", `"bot_token3": "xoxb-47834520726-N3otsrwj8Cf99cs8GhiRZsX1"`, "xoxb-47834520726-N3otsrwj8Cf99cs8GhiRZsX1"),
		Match("true positive 4", `"bot_token4": "xoxb-123456789012-Xw937qtWSXJss1lFaKe"`, "xoxb-123456789012-Xw937qtWSXJss1lFaKe"),
		Match("true positive 5", `"bot_token5": "xoxb-312554961652-uSmliU84rFhnUSBq9YdKh6lS"`, "xoxb-312554961652-uSmliU84rFhnUSBq9YdKh6lS"),
		Match("true positive 6", `"bot_token6": "xoxb-51351043345-Lzwmto5IMVb8UK36MghZYMEi"`, "xoxb-51351043345-Lzwmto5IMVb8UK36MghZYMEi"),
		Match("true positive 7", `"bot_token7": "xoxb-130154379991-ogFL0OFP3w6AwdJuK7wLojpK"`, "xoxb-130154379991-ogFL0OFP3w6AwdJuK7wLojpK"),
		Match("true positive 8", `"bot_token8": "xoxb-159279836768-FOst5DLfEzmQgkz7cte5qiI"`, "xoxb-159279836768-FOst5DLfEzmQgkz7cte5qiI"),
		Match("true positive 9", `"bot_token9": "xoxb-50014434-slacktokenx29U9X1bQ"`, "xoxb-50014434-slacktokenx29U9X1bQ"),
		Match("true positive 10", `"bot_token10": "xoxb-1779185060-5fbbd6p84oe7ut4qrttebiwa`, "xoxb-1779185060-5fbbd6p84oe7ut4qrttebiwa"),
		Match("true positive 11", `"bot_token11": "xoxb-177918506041-5fbbd6p84oe7ut4qrttebiw`, "xoxb-177918506041-5fbbd6p84oe7ut4qrttebiw"),
		NoMatch("false positive 1", "xoxb-xxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx"),
		NoMatch("false positive 2", "xoxb-Slack_BOT_TOKEN"),
		NoMatch("false positive 3", "xoxb-abcdef-abcdef"),
	},
})

// Reference: https://api.slack.com/authentication/token-types#workspace
var _ = Add(config.Rule{
	ID:          "slack-legacy-workspace-token",
	Confidence:  "high",
	Description: "Identified a Slack Legacy Workspace token, potentially compromising access to workspace data and legacy features.",
	// This is by far the least confident pattern.
	Regex: `xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48}`,
	Keywords: []string{
		"xoxa",
		"xoxr",
	},
	FilterExpr: `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		Match("slack assignment", `slackToken = "xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c"`, "xoxa-2-511111111"),
		Match("true positive 1", `"access_token": "xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c"`, "xoxa-2-511111111"),
		Match("true positive 2", `"access_token1": "xoxa-1-5fbbd6p84oe7`, "xoxa-1-5fbbd6p84oe7"),
		Match("true positive 3", `"access_token2": "xoxa-5fbbd6p84oe7`, "xoxa-5fbbd6p84oe7"),
		Match("true positive 4", `"refresh_token1": "xoxr-1-5fbbd6p84oe7`, "xoxr-1-5fbbd6p84oe7"),
		Match("true positive 5", `"refresh_token2": "xoxr-5fbbd6p84oe7`, "xoxr-5fbbd6p84oe7"),
		NoMatch(`"xoxa-faketoken", "xoxa-access-token-string", "XOXa-nx991k",`, "https://github.com/xoxa-nyc/xoxa-nyc.github.io/blob/master/README.md"),
	},
})

// References:
// - https://api.slack.com/authentication/token-types#legacy
// - https://api.slack.com/changelog/2016-05-19-authorship-changing-for-older-tokens
// - https://github.com/jonz-secops/TokenTester/blob/978e9f3eabc7e9978769cfbba10735afa3bf627e/slack#L29
// - https://gist.github.com/thesubtlety/a1c460d53df0837c5817c478b9f10588#file-local-slack-jack-py-L32
var _ = Add(config.Rule{
	ID:          "slack-legacy-token",
	Confidence:  "high",
	Description: "Detected a Slack Legacy token, risking unauthorized access to older Slack integrations and user data.",
	Regex:       `xox[os]-\d+-\d+-\d+-[a-fA-F\d]+`,
	Keywords:    []string{"xoxo", "xoxs"},
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		Match("slack assignment", `slackToken = "xoxs-416843729158-132049654-5609968301-e708ba56e1"`, "xoxs-416843729158-132049654-5609968301-e708ba56e1"),
		Match("true positive 1", `"access_token1": "xoxs-3206092076-3204538285-3743137121-836b042620"`, "xoxs-3206092076-3204538285-3743137121-836b042620"),
		Match("true positive 2", `"access_token2": "xoxs-416843729158-132049654-5609968301-e708ba56e1"`, "xoxs-416843729158-132049654-5609968301-e708ba56e1"),
		Match("true positive 3", `"access_token3": "xoxs-420083410720-421837374423-440811613314-977844f625b707d5b0b268206dbc92cbc85feef3e71b08e44815a8e6e7657190"`, "xoxs-420083410720-421837374423-440811613314-977844f625b707d5b0b268206dbc92cbc85feef3e71b08e44815a8e6e7657190"),
		Match("true positive 4", `"access_token4": "xoxs-4829527689-4829527691-4814341714-d0346ec616"`, "xoxs-4829527689-4829527691-4814341714-d0346ec616"),
		Match("true positive 5", `"access_token5": "xoxs-155191149137-155868813314-338998331396-9f6d235915"`, "xoxs-155191149137-155868813314-338998331396-9f6d235915"),
		Match("true positive 6", `"access_token7": "xoxo-523423-234243-234233-e039d02840a0b9379c"`, "xoxo-523423-234243-234233-e039d02840a0b9379c"),
		NoMatch("false positive 1", "https://indieweb.org/images/3/35/2018-250-xoxo-indieweb-1.jpg"),
		NoMatch("false positive 2", "https://lh3.googleusercontent.com/-tWXjX3LUD6w/Ua4La_N5E2I/AAAAAAAAACg/qcm19xbEYa4/s640/EXO-XOXO-teaser-exo-k-34521098-720-516.jpg"),
	},
})

var _ = Add(config.Rule{
	ID:          "slack-webhook-url",
	Confidence:  "high",
	Description: "Discovered a Slack Webhook, which could lead to unauthorized message posting and data leakage in Slack channels.",
	// If this generates too many false positives, add a filter (for example, "xxxx" or "00000").
	Regex: `(?:https?://)?hooks.slack.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}`,
	Keywords: []string{
		"hooks.slack.com",
	},
	Tests: []config.RuleTest{
		Match("bare secret", "hooks.slack.com/services/5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar", "hooks.slack.com/services/5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar"),
		Match("bare secret 2", "http://hooks.slack.com/services/5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1", "http://hooks.slack.com/services/5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1"),
		Match("bare secret 3", "https://hooks.slack.com/services/5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1r", "https://hooks.slack.com/services/5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7lipmar1r"),
		Match("bare secret 4", "http://hooks.slack.com/services/T024TTTTT/BBB72BBL/AZAAA9u0pA4ad666eMgbi555", "http://hooks.slack.com/services/T024TTTTT/BBB72BBL/AZAAA9u0pA4ad666eMgbi555"),
		Match("bare secret 5", "https://hooks.slack.com/services/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", "https://hooks.slack.com/services/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"),
		Match("bare secret 6", "hooks.slack.com/workflows/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", "hooks.slack.com/workflows/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"),
		Match("bare secret 7", "http://hooks.slack.com/workflows/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", "http://hooks.slack.com/workflows/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"),
		Match("bare secret 8", "https://hooks.slack.com/workflows/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", "https://hooks.slack.com/workflows/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"),
		Match("true positive 1", "https://hooks.slack.com/workflows/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", "https://hooks.slack.com/workflows/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"),
		Match("true positive 2", "http://hooks.slack.com/workflows/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", "http://hooks.slack.com/workflows/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"),
		Match("bare secret 9", "https://hooks.slack.com/triggers/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", "https://hooks.slack.com/triggers/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"),
	},
})

// SlackSessionCookie detects xoxd- session cookies, used for authenticating browser and desktop clients.
//
// References:
// - https://slack.engineering/catching-compromised-cookies/
// - https://www.papermtn.co.uk/retrieving-and-using-slack-cookies-for-authentication/
// - https://blog.tw1sm.io/p/abusing-slack-for-offensive-operations
var _ = Add(config.Rule{
	ID:          "slack-session-cookie",
	Confidence:  "high",
	Description: "Detected a Slack session cookie (xoxd-), which authenticates browser and desktop sessions across all of a user's workspaces.",
	Regex:       `(xoxd-[\w\/\\+-]{100,}={0,2})(?:[^\w\/+=-]|\z)`,
	Keywords:    []string{"xoxd-"},
	FilterExpr:  `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		Match("slack assignment", `slackToken = "xoxd-MKJooWNJVMRjVCvp59SGgjp-CkyNG/fF50D40mQMYgYo6YlZ\LXaRuJgCTKjox-SRvV+YTrh7Da_fclR3muIuhMhquj2-K0wGC3c="`, `xoxd-MKJooWNJVMRjVCvp59SGgjp-CkyNG/fF50D40mQMYgYo6YlZ\LXaRuJgCTKjox-SRvV+YTrh7Da_fclR3muIuhMhquj2-K0wGC3c=`),
		Match("true positive 1", `"XOXD_TOKEN = "xoxd-RWAqM1zwIRrr+2XACnx2j85Nmnq7jXRq08nLu92OuSVSD/Oq/JrB6huw+1E7SYpflbEhm7gKHZsqNX3mypdDoskW+s9x+DXCS74jne9GFhai5C8C5pxXVy60iJT/U685IypCMgGzGnIiGmv03u+QU/CuEBtrLAVOjxqeLlunHjtjotJQAgBX2fJuQVq59uDyGb7SNSH5YWJEFrqdJFA6i0nxDrY2"`, "xoxd-RWAqM1zwIRrr+2XACnx2j85Nmnq7jXRq08nLu92OuSVSD/Oq/JrB6huw+1E7SYpflbEhm7gKHZsqNX3mypdDoskW+s9x+DXCS74jne9GFhai5C8C5pxXVy60iJT/U685IypCMgGzGnIiGmv03u+QU/CuEBtrLAVOjxqeLlunHjtjotJQAgBX2fJuQVq59uDyGb7SNSH5YWJEFrqdJFA6i0nxDrY2"),
		NoMatch("false positive 1", `"cookie": "xoxd-abcdef1234567890..."`),
		NoMatch("false positive 2", ` :cookie "xoxd-sssssssssss-88888888888-hhhhhhhhhhh-jjjjjjjjjj; d-s=888888888888; lc=888888888888"`),
		NoMatch("https://github.com/Alcaro/russian-malware/blob/4bfa0c58532eb234c6cee4bcf7f612a4063adab3/slack.cpp#L151", "string m_cookie_xoxd; // xoxd-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8= (but longer)"),
	},
})

// SlackSessionToken is a short-lived companion to SlackSessionCookie.
var _ = Add(config.Rule{
	ID:          "slack-session-token",
	Confidence:  "high",
	Description: "Detected a Slack client session token (xoxc-), which provides full user-level API access when paired with a session cookie.",
	Regex:       `xoxc-\d{9,15}-\d{9,15}-\d{9,15}-[a-f0-9]{64}\b`,
	Keywords:    []string{"xoxc-"},
	FilterExpr:  `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		Match("slack assignment", `slackToken = "xoxc-177918506-041298415-765688777-86758bf5c97d2d2a313e4f95957818a7b3edca492f2b8a67697c4f91d9b9332e"`, "xoxc-177918506-041298415-765688777-86758bf5c97d2d2a313e4f95957818a7b3edca492f2b8a67697c4f91d9b9332e"),
		Match("true positive 1", `    "------WebKitFormBoundaryPBGcj8sy358Z0vNT\r\nContent-Disposition: form-data; name": '"profile"\r\n\r\n{"status_emoji":":tada:","status_expiration":1645052399,"status_text":"","status_text_canonical":""}\r\n------WebKitFormBoundaryPBGcj8sy358Z0vNT\r\nContent-Disposition: form-data; name="token"\r\n\r\n xoxc-2541715624-2536568458595-2560197464944-23a188852dc1e585a9b594b4facd7d96339fb1d45c592c67a2385fb02f3cd453\r\n------WebKitFormBoundaryPBGcj8sy358Z0v`, "xoxc-2541715624-2536568458595-2560197464944-23a188852dc1e585a9b594b4facd7d96339fb1d45c592c67a2385fb02f3cd453"),
		NoMatch("false positive 1", "\tTestClientToken   = \"xoxc-888888888888-888888888888-8888888888888-fffffffffffffffa915fe069d70a8ad81743b0ec4ee9c81540af43f5e143264b\""),
	},
})
