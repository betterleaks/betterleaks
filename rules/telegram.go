package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	Description: "Detected a Telegram Bot API Token, risking unauthorized bot operations and message interception on Telegram.",
	ID:          "telegram-bot-api-token",
	Confidence:  "high",

	Regex: Assignment([]string{"telegr"}, "(?i)[0-9]{5,16}:(?-i:A)[a-z0-9_\\-]{34}"),
	Keywords: []string{
		"telegr",
	},
	Tests: []config.RuleTest{
		Match("telegram assignment", `telegramToken = "17791850:A--wfu0y1vd_3l1cmfzxoud8et6xy88z3po"`, "17791850:A--wfu0y1vd_3l1cmfzxoud8et6xy88z3po"),
		Match("telegram assignment 2", `telegramToken = "17791:A7z---wfu0y1vd_3l1cmfzxoud8et6xy88z"`, "17791:A7z---wfu0y1vd_3l1cmfzxoud8et6xy88z"),
		Match("telegram assignment 3", `telegramToken = "1779185060412984:Avd_3l1cmfzxoud8et6xy88z3pomb2z7epj"`, "1779185060412984:Avd_3l1cmfzxoud8et6xy88z3pomb2z7epj"),
		Match("true positive 1", "TELEGRAM_API_TOKEN = 17791850:A--wfu0y1vd_3l1cmfzxoud8et6xy88z3po", "17791850:A--wfu0y1vd_3l1cmfzxoud8et6xy88z3po"),
		Match("true positive 2", "telegram bot: 17791850:A--wfu0y1vd_3l1cmfzxoud8et6xy88z3po", "17791850:A--wfu0y1vd_3l1cmfzxoud8et6xy88z3po"),
		NoMatch("Token with too small bot_id", `telegram_api_token = "1779:A67z---wfu0y1vd_3l1cmfzxoud8et6xy88"`),
		NoMatch("Token with too big bot_id", `telegram_api_token = "17791850604129841:Ad_3l1cmfzxoud8et6xy88z3pomb2z7epjl"`),
		NoMatch("XSD file containing the string AgencyIdentificationCodeContentType", `telegram_api_token = "<xsd:element name="AgencyIdentificationCode" type="clm17791:AgencyIdentificationCodeContentType"/>"`),
		NoMatch("false positive 1", `telegram_api_token = "token:"clm17791:AgencyIdentificationCodeContentType""`),
		NoMatch("false positive 2", `telegram_api_token = "<xsd:element name="AgencyIdentificationCode" type="clm17791850:AgencyIdentificationCodeContentType"/>"`),
		NoMatch("Prefix and suffix variations that shouldn't match", `telegram_api_token = "telegram_api_token = "17791850:Ahello--wfu0y1vd_3l1cmfzxoud8et6xy88z3po""`),
		NoMatch("false positive 3", `telegram_api_token = "telegram_api_token = "17791850:A-some-other-thing---wfu0y1vd_3l1cmfzxoud8et6xy88z3po""`),
		NoMatch("false positive 4", `telegram_api_token = "telegram_api_token = "17791850:A_--wfu0y1vd_3l1cmfzxoud8et6xy88z3po""`),
		NoMatch("false positive 5", `telegram_api_token = "telegram_api_token = "17791850:A--wfu0y1vd_3l1cmfzxoud8et6xy88z3pohello""`),
		NoMatch("false positive 6", `telegram_api_token = "telegram_api_token = "17791850:A--wfu0y1vd_3l1cmfzxoud8et6xy88z3po-some-other-thing""`),
		NoMatch("false positive 7", `telegram_api_token = "telegram_api_token = "17791850:A_--wfu0y1vd_3l1cmfzxoud8et6xy88z3po_""`),
	},
})
