package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func GenericPassword() *config.Rule {
	passwordAssignmentRegex := `(?:passw(?:or)?d|psw|[_.-]pw)\b[ \t'"\\]{0,3}(?:=>|:=|=|:)[ \t]{0,5}(?:"((?:\\.|[^"\\\r\n]){5,250})"|'((?:\\.|[^'\\\r\n]){5,250})'|\x60((?:\\.|[^\x60\\\r\n]){5,250})\x60|([^:=\s'"\x60,;][^\s'"\x60,;]{4,249}))(?:[ \t]*[,;)}\]\r\n]|[ \t]*$|\\[nr])`
	authArgumentRegex := `\b(?:login|log[_.-]?in|authenticate)\b[ \t]*\([ \t]*[^,()\r\n]{1,250}[ \t]*,[ \t]*(?:"((?:\\.|[^"\\\r\n]){5,250})"|'((?:\\.|[^'\\\r\n]){5,250})'|\x60((?:\\.|[^\x60\\\r\n]){5,250})\x60)[ \t]*\)`

	r := config.Rule{
		RuleID:      "generic-password",
		Confidence:  "low",
		Description: "Detected a potential hardcoded password literal, which may expose account credentials.",
		Regex:       regexp.MustCompile(`(?i)(?:` + passwordAssignmentRegex + `|` + authArgumentRegex + `)`),
		Keywords:    []string{"passw", "psw", "_pw", "-pw", ".pw", "login", "log_in", "log-in", "authenticate"},
		Specificity: 20,
		Components: []*config.Component{
			{
				RuleID:   "generic-username",
				Optional: true,
				Within:   "7L,200C",
			},
		},
		Filter: `// Restrict nearby evidence to the password's line and the
// six lines on either side. The password key itself is intentionally excluded
// from the evidence patterns below.
let raw = finding["fragment_raw"];
let beforeLines = split(raw[
  max(finding["match_start_idx"] - 8192, 0):finding["match_start_idx"]
], "\n");
let afterLines = split(raw[
  finding["match_end_idx"]:min(finding["match_end_idx"] + 8192, len(raw))
], "\n");
let nearbyContext =
  join(beforeLines[max(len(beforeLines) - 7, 0):], "\n")
  + "\n"
  + join(afterLines[:min(len(afterLines), 7)], "\n");

let hasAuthContext = filter.matchesAny(nearbyContext, [
  // Authentication and connection calls.
  ` + "`(?i)\\b(?:auth(?:enticate|entication)?|login|log[_.-]?in|sign[_.-]?in|connect(?:ion)?|open[_.-]?(?:connection|session)|create[_.-]?(?:connection|session)|bind)\\b[ \\t]*\\(`" + `,
  // Credential and connection configuration containers.
  ` + "`(?i)\\b(?:basic[_.-]?auth|auth(?:entication)?[_.-]?(?:config|options|params)|credentials?|login[_.-]?(?:config|options|params)|connection[_.-]?(?:string|config|options|params)|data[_.-]?source|dsn)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:|\\{|\\()`" + `,
  // Assets commonly paired with credentials.
  ` + "`(?i)\\b(?:host(?:name)?|server|endpoint|database|db[_.-]?(?:name|host|url)|port|jdbc[_.-]?url|connection[_.-]?url)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]{0,5}(?:\"[^\"\\r\\n]+\"|'[^'\\r\\n]+'|\\x60[^\\x60\\r\\n]+\\x60|[^\\s,;)}\\]]+)`" + `,
  // Authentication-bearing connection strings.
  ` + "`(?i)\\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\\+srv)?|redis|amqps?|ldaps?|smtps?|ftps?|ssh)://`" + `
]);
let hasUsernameContext = filter.matchesAny(nearbyContext, [
  ` + "`(?im)(?:^|[^a-z0-9])(?:username|user|login(?:[_.-]?name)?|email(?:[_.-]?address)?|uid|account(?:[_.-]?name)?|client(?:[_.-]?(?:id|name))?)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)`" + `
]);
let isAuthArgument = filter.matchesAny(finding["match"], [
  ` + "`(?i)\\b(?:login|log[_.-]?in|authenticate)\\b[ \\t]*\\(`" + `
]);
let isCodeFile = filter.matchesAny(attributes["path"], [
  ` + "`(?i)\\.(?:c|cc|cpp|cxx|h|hh|hpp|cs|dart|ex|exs|fs|fsx|go|groovy|java|js|jsx|mjs|cjs|kt|kts|lua|m|mm|php|pl|pm|py|pyw|r|rb|rs|scala|sql|swift|tf|tfvars|ts|tsx|vb|vue)(?:\\.(?:example|sample|template))?$`" + `
]);
let isUnquotedCodeValue = isCodeFile && filter.matchesAny(finding["match"], [
  ` + "`^(?i:passw(?:or)?d|psw|[_.-]pw)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*[^\\x22\\x27\\x60 \\t\\r\\n]`" + `
]);

let level = (
  isAuthArgument
  || (hasAuthContext && hasUsernameContext)
) ? "medium" : "low";
let _ = filter.setConfidence(level);

filter.matchesAny(finding["secret"], [
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
  ` + "`^\\$[A-Za-z_][A-Za-z0-9_]*$`" + `,
  ` + "`(?i)^\\$env:[A-Za-z_][A-Za-z0-9_]*$`" + `,
  ` + "`^%[A-Za-z_][A-Za-z0-9_]*%$`" + `,
  ` + "`^<[^>]+>$`" + `,
  ` + "`^<[^>\\s]+$`" + `,
  ` + "`^\\{[^}]+}$`" + `,
  ` + "`^(?:PASSWORD|PASSWD|YOUR_PASSWORD)$`" + `,
  ` + "`(?i)^(?:your[_-]?password|example[_-]?password|placeholder|forbidden_value)$`" + `,
  ` + "`^\\([A-Za-z_][A-Za-z0-9_.]*(?:[ \\t]+[A-Za-z_][A-Za-z0-9_.]*)*\\)$`" + `,
  ` + "`^\\$2[abxy]\\$[0-9]{2}\\$[./A-Za-z0-9]{7,}$`" + `,
  ` + "`(?i)^\\$pbkdf2[-_][^$]+\\$.*$`" + `
])
|| isUnquotedCodeValue
|| filter.matchesAny(finding["match"], [
  ` + "`(?i:passw(?:or)?d|psw|[_.-]pw)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*(?i:nil|null|none|undefined|true|false|string|str|text|integer|int|number|boolean|bool|object)(?:[ \\t]*[,;)}\\]\\r\\n]|[ \\t]*$|\\\\[nr])`" + `,
  ` + "`(?i:passw(?:or)?d|psw|[_.-]pw)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*(?:[$@][A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)*|:[A-Za-z_][A-Za-z0-9_]*|(?:::)?[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*::[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*|(?i:process\\.env|config|settings|credentials?|secrets?|var|local|module|data)(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\])+|[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*(?:\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)*|[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*\\.(?i:(?:[a-z0-9]+_)*(?:passw(?:or)?d|psw|token|secret|hex)))[)}\\]]*\\\\?(?:[ \\t]*[,;)}\\]\\r\\n]|[ \\t]*$|\\\\[nr])`" + `
])`,
	}

	tps := []string{
		`password: hunter2`,
		`password: Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB`,
		`password = "the quick brown fox jumps over lazy dogs"`,
		`password = "MyPassword123!"`,
		"credentials: {\nusername: alice\npassword: hunter2\n}",
		"USERNAME=alice@example.com\nPASSWORD=hunter2",
		"login({\nusername = process.env.USERNAME\npasswd = \"g4F!mQ8#vZ2@rT6$xK9\"\n})",
		"auth_config: {\npsw: hunter2\n}",
		"database.host = db.internal\ndatabase_pw = \"J8s!vR4#qL7@nT2$xM6\"",
		"service.connect(\n  service-pw: Qv7D0LXCM3EIMbgJpUNnkRtOfOueHznB\n)",
		"dsn: postgres://db.internal/app\nclient.pw = \"m4F!qK8#zR2@tV6$xN9\"",
		"login({\n  \"password\": \"#exFfrbtEpo&RaTkZ#%*zFgS\"\n})",
		`smtp.login(username, "hunter2")`,
		`client.authenticate(user, "password1")`,
		`service.log_in(account, 'correct horse battery staple')`,
	}
	fps := []string{
		`password: four`,
		"username: alice\npassword = process.env.PASSWORD",
		"database.host = db.internal\ndatabase_pw = undefined",
		"username: alice\npassword = \"your_password\"",
		`postgres://user:hunter2@example.com/db`,
		`ldap.bind(user, "hunter2")`,
	}
	return utils.Validate(r, tps, fps)
}

func GenericUsername() *config.Rule {
	r := config.Rule{
		RuleID:      "generic-username",
		Confidence:  "low",
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
		Filter: `// An unquoted value is an ambiguous scalar in configuration, but
// not a string literal in the source languages recognized below.
let isCodeFile = filter.matchesAny(attributes["path"], [
  ` + "`(?i)\\.(?:c|cc|cpp|cxx|h|hh|hpp|cs|dart|ex|exs|fs|fsx|go|groovy|java|js|jsx|mjs|cjs|kt|kts|lua|m|mm|php|pl|pm|py|pyw|r|rb|rs|scala|sql|swift|tf|tfvars|ts|tsx|vb|vue)(?:\\.(?:example|sample|template))?$`" + `
]);
let isUnquotedCodeValue = isCodeFile && filter.matchesAny(finding["match"], [
  ` + "`^(?:[^a-zA-Z0-9])?(?i:username|user|login(?:[_.-]?name)?|email(?:[_.-]?address)?|uid|account(?:[_.-]?name)?|client(?:[_.-](?:id|name))?)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*[^\\x22\\x27\\x60 \\t\\r\\n]`" + `
]);

isUnquotedCodeValue
|| filter.matchesAny(finding["secret"], [
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
