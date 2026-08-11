package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func GenericPassword() *config.Rule {
	r := config.Rule{
		RuleID:      "generic-password",
		Description: "Detected a username and password combination in close proximity, which may expose account credentials.",
		Regex:       regexp.MustCompile(`(?i)(?:passw(?:or)?d)\b[ \t'"\\]{0,3}(?:=>|:=|=|:)[ \t]{0,5}(?:"((?:\\.|[^"\\\r\n]){5,250})"|'((?:\\.|[^'\\\r\n]){5,250})'|\x60((?:\\.|[^\x60\\\r\n]){5,250})\x60|([^:=\s'"\x60,;][^\s'"\x60,;]{4,249}))(?:[ \t]*[,;)}\]\r\n]|[ \t]*$|\\[nr])`),
		Keywords:    []string{"passw"},
		Specificity: 20,
		Components: []*config.Component{
			{
				RuleID:   "generic-username",
				Optional: true,
				Within:   "15L,200C",
			},
		},
		Filter: `filter.entropy(finding["secret"]) <= 3.5
|| filter.failsTokenEfficiency(finding["secret"])
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
  ` + "`(?i:passw(?:or)?d)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*(?i:nil|null|none|undefined|true|false|string|str|text|integer|int|number|boolean|bool|object)(?:[ \\t]*[,;)}\\]\\r\\n]|[ \\t]*$|\\\\[nr])`" + `,
  ` + "`(?i:passw(?:or)?d)\\b[ \\t'\"\\\\]{0,3}(?:=>|:=|=|:)[ \\t]*(?:[$@][A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)*|:[A-Za-z_][A-Za-z0-9_]*|(?:::)?[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*::[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*|(?i:process\\.env|config|settings|credentials?|secrets?|var|local|module|data)(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\])+|[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*(?:\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*|\\[[^]\\r\\n]+\\]|\\([^,\\r\\n)]*\\)?)*|[A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::)[A-Za-z_][A-Za-z0-9_]*)*\\.(?i:(?:[a-z0-9]+_)*(?:passw(?:or)?d|token|secret|hex)))[)}\\]]*\\\\?(?:[ \\t]*[,;)}\\]\\r\\n]|[ \\t]*$|\\\\[nr])`" + `
])`,
	}

	tps := []string{
		`password: Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB`,
		`passwd = "g4F!mQ8#vZ2@rT6$xK9"`,
		`"password": "#exFfrbtEpo&RaTkZ#%*zFgS"`,
	}
	fps := []string{
		`password: four`,
		`password: hunter2`,
		`password = "the quick brown fox jumps over lazy dogs"`,
		`password = process.env.PASSWORD`,
		`password = "your_password"`,
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
