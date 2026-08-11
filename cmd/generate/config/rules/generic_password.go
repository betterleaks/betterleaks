package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func GenericPassword() *config.Rule {
	r := config.Rule{
		RuleID:      "generic-password",
		Description: "Detected a password in authentication context, which may expose account credentials.",
		Regex:       regexp.MustCompile(`(?i)(?:passw(?:or)?d|[_.-]pw)\b[ \t'"\\]{0,3}(?:=>|:=|=|:)[ \t]{0,5}(?:"((?:\\.|[^"\\\r\n]){5,250})"|'((?:\\.|[^'\\\r\n]){5,250})'|\x60((?:\\.|[^\x60\\\r\n]){5,250})\x60|([^:=\s'"\x60,;][^\s'"\x60,;]{4,249}))(?:[ \t]*[,;)}\]\r\n]|[ \t]*$|\\[nr])`),
		Keywords:    []string{"passw", "_pw", "-pw", ".pw"},
		Specificity: 20,
		Components: []*config.Component{
			{
				RuleID:   "generic-username",
				Optional: true,
				Within:   "7L,200C",
			},
		},
		Filter: `// Restrict authentication evidence to the password's line and the
// six lines on either side. The password key itself is intentionally excluded
// from the evidence patterns below.
let raw = finding["fragment_raw"];
let beforeLines = split(raw[
  max(finding["match_start_idx"] - 8192, 0):finding["match_start_idx"]
], "\n");
let afterLines = split(raw[
  finding["match_end_idx"]:min(finding["match_end_idx"] + 8192, len(raw))
], "\n");
let authContext =
  join(beforeLines[max(len(beforeLines) - 7, 0):], "\n")
  + "\n"
  + join(afterLines[:min(len(afterLines), 7)], "\n");

!filter.matchesAny(authContext, [
  // Username/account assignments. The value may be dynamic: the assignment
  // still proves that the nearby literal password participates in auth.
  ` + "`(?im)(?:^|[^a-zA-Z0-9])(?i:username|user|login(?:[_.-]name)?|email(?:[_.-]address)?|uid|account(?:[_.-]name)?|client(?:[_.-](?:id|name))?)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]{0,5}(?:\"[^\"\\r\\n]{1,250}\"|'[^'\\r\\n]{1,250}'|\\x60[^\\x60\\r\\n]{1,250}\\x60|[^\\s,;)}\\]]{1,250})`" + `,
  // Authentication and connection calls.
  ` + "`(?i)\\b(?:auth(?:enticate|entication)?|login|log[_.-]?in|sign[_.-]?in|connect(?:ion)?|open[_.-]?(?:connection|session)|create[_.-]?(?:connection|session)|bind)\\b[ \\t]*\\(`" + `,
  // Credential and connection configuration containers.
  ` + "`(?i)\\b(?:basic[_.-]?auth|auth(?:entication)?[_.-]?(?:config|options|params)|credentials?|login[_.-]?(?:config|options|params)|connection[_.-]?(?:string|config|options|params)|data[_.-]?source|dsn)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:|\\{|\\()`" + `,
  // Assets commonly paired with credentials.
  ` + "`(?i)\\b(?:host(?:name)?|server|endpoint|database|db[_.-]?(?:name|host|url)|port|jdbc[_.-]?url|connection[_.-]?url)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]{0,5}(?:\"[^\"\\r\\n]+\"|'[^'\\r\\n]+'|\\x60[^\\x60\\r\\n]+\\x60|[^\\s,;)}\\]]+)`" + `,
  // Authentication-bearing connection strings.
  ` + "`(?i)\\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\\+srv)?|redis|amqps?|ldaps?|smtps?|ftps?|ssh)://`" + `
])
|| filter.matchesAny(finding["secret"], [
  ` + "`^\\*+$`" + `,
  ` + "`^\\.+$`" + `,
  ` + "`(?i)^x{4,}$`" + `,
  ` + "`(?i)^\\[?(?:redacted|masked|filtered)\\]?$`" + `,
  ` + "`^•+$`" + `,
  ` + "`^\\$\\{.*}$`" + `,
  ` + "`^\\$\\([^\\r\\n]+\\)$`" + `,
  ` + "`^#\\{[^}\\r\\n]+}$`" + `,
  ` + "`^\\{\\{[ \\t]*.+[ \\t]*}}$`" + `,
  ` + "`^%\\{[^}]+}$`" + `,
  ` + "`^<[^>]+>$`" + `,
  ` + "`^<[^>\\s]+$`" + `,
  ` + "`^\\{[^}]+}$`" + `,
  ` + "`^(?:PASSWORD|PASSWD|YOUR_PASSWORD)$`" + `,
  ` + "`(?i)^(?:your[_-]?password|example[_-]?password|placeholder|forbidden_value)$`" + `,
  ` + "`(?i)password`" + `,
  ` + "`^\\([A-Za-z_][A-Za-z0-9_.]*(?:[ \\t]+[A-Za-z_][A-Za-z0-9_.]*)*\\)$`" + `,
  ` + "`^\\$2[abxy]\\$[0-9]{2}\\$[./A-Za-z0-9]{7,}$`" + `,
  ` + "`(?i)^\\$pbkdf2[-_][^$]+\\$.*$`" + `
])
|| filter.matchesAny(finding["match"], [
  ` + "`(?i:passw(?:or)?d|[_.-]pw)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*(?i:nil|null|none|undefined|true|false|string|str|text|integer|int|number|boolean|bool|object)(?:[ \\t]*[,;)}\\]\\r\\n]|[ \\t]*$|\\\\[nr])`" + `,
  ` + "`(?i:passw(?:or)?d|[_.-]pw)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*(?:[$@][A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)*|:[A-Za-z_][A-Za-z0-9_]*|(?:::)?[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*::[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*|(?i:process\\.env|config|settings|credentials?|secrets?|var|local|module|data)(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\])+|[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*(?:\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)*|[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*\\.(?i:(?:[a-z0-9]+_)*(?:passw(?:or)?d|token|secret|hex)))[)}\\]]*\\\\?(?:[ \\t]*[,;)}\\]\\r\\n]|[ \\t]*$|\\\\[nr])`" + `
])`,
	}

	tps := []string{
		"username: alice\npassword: hunter2",
		"username = process.env.USERNAME\npasswd = \"g4F!mQ8#vZ2@rT6$xK9\"",
		"database.host = db.internal\ndatabase_pw = \"J8s!vR4#qL7@nT2$xM6\"",
		"service.connect(\n  service-pw: Qv7D0LXCM3EIMbgJpUNnkRtOfOueHznB\n)",
		"dsn: postgres://db.internal/app\nclient.pw = \"m4F!qK8#zR2@tV6$xN9\"",
		"login({\n  \"password\": \"#exFfrbtEpo&RaTkZ#%*zFgS\"\n})",
	}
	fps := []string{
		`password: four`,
		`password: hunter2`,
		`password: Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB`,
		`password = "the quick brown fox jumps over lazy dogs"`,
		"username: alice\npassword = process.env.PASSWORD",
		"database.host = db.internal\ndatabase_pw = undefined",
		"username: alice\npassword = \"your_password\"",
	}
	return utils.Validate(r, tps, fps)
}

func GenericUsername() *config.Rule {
	r := config.Rule{
		RuleID:      "generic-username",
		Description: "Detected a username-like value used as a component of the generic-password rule.",
		Regex:       regexp.MustCompile(`(?m)(?:^|[^a-zA-Z0-9])(?i:username|user|login(?:[_.-]name)?|email(?:[_.-]address)?|uid|account(?:[_.-]name)?|client(?:[_.-](?:id|name))?)\b[ \t'"\\]{0,3}(?:=>|:=|=|:)[ \t]{0,5}(?:"((?:\\.|[^"\\\r\n]){3,250})"|'((?:\\.|[^'\\\r\n]){3,250})'|\x60((?:\\.|[^\x60\\\r\n]){3,250})\x60|([^:=\s'"\x60,;][^\s'"\x60,;]{2,249}))(?:[ \t]*[,;)}\]\r\n]|[ \t]*$|\\[nr])`),
		Keywords: []string{
			"user",
			"login",
			"email",
			"uid",
			"account",
			"client",
		},
		SkipReport: true,
		Filter: `// Plain identifiers such as currentUser are valid ambiguous scalars.
// Discard only exact placeholders and values with explicit expression syntax.
filter.matchesAny(finding["secret"], [
  ` + "`^\\*+$`" + `,
  ` + "`^\\.+$`" + `,
  ` + "`(?i)^x{4,}$`" + `,
  ` + "`^•+$`" + `,
  ` + "`^\\$\\{.*}$`" + `,
  ` + "`^\\$\\([^\\r\\n]+\\)$`" + `,
  ` + "`^#\\{[^}\\r\\n]+}$`" + `,
  ` + "`^\\{\\{[ \\t]*.+[ \\t]*}}$`" + `,
  ` + "`^%\\{[^}]+}$`" + `,
  ` + "`^<[^>]+>$`" + `,
  ` + "`^<[^>\\s]+$`" + `,
  ` + "`^\\{[^}]+}$`" + `,
  ` + "`(?i)^\\[?(?:redacted|masked|filtered)\\]?$`" + `,
  ` + "`^(?:USERNAME|USER_NAME|USER|LOGIN|LOGIN_NAME|ACCOUNT_NAME|EMAIL|EMAIL_ADDRESS|UID|CLIENT|CLIENT_ID|CLIENT_NAME)$`" + `,
  ` + "`(?i)^(?:your|example)[_-]?(?:username|user_name|user|login|login_name|account_name|email|email_address|uid|client(?:_id|_name)?)$`" + `
])
|| filter.matchesAny(finding["match"], [
  ` + "`(?i:username|user|login(?:[_.-]name)?|email(?:[_.-]address)?|uid|account(?:[_.-]name)?|client(?:[_.-](?:id|name))?)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*(?i:nil|null|none|undefined|true|false|string|str|text|integer|int|number|boolean|bool|object)(?:[ \\t]*[,;)}\\]\\r\\n]|[ \\t]*$|\\\\[nr])`" + `,
  ` + "`(?i:username|user|login(?:[_.-]name)?|email(?:[_.-]address)?|uid|account(?:[_.-]name)?|client(?:[_.-](?:id|name))?)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*(?:[$@][A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)*|:[A-Za-z_][A-Za-z0-9_]*|(?:::)?[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*::[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*|(?i:process\\.env|config|settings|credentials?|secrets?|var|local|module|data)(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\])+|[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*(?:\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)*|[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*\\.(?i:(?:[a-z0-9]+_)*(?:username|user|login(?:_name)?|email(?:_address)?|uid|account(?:_name)?|client(?:_(?:id|name))?|id)))[)}\\]]*\\\\?(?:[ \\t]*[,;)}\\]\\r\\n]|[ \\t]*$|\\\\[nr])`" + `
])`,
	}

	tps := []string{
		`username: alice`,
		`login = "alice@example.com"`,
		`client_id: service-client`,
	}
	fps := []string{
		`user: me`,
		`username = process.env.USERNAME`,
		`username = "your_username"`,
	}
	return utils.Validate(r, tps, fps)
}
