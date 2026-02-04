package rules

import (
	"github.com/betterleaks/betterleaks/config"
	utils2 "github.com/betterleaks/betterleaks/config/generate/utils"
	"github.com/betterleaks/betterleaks/config/generate/utils/secrets"
)

func TelegramBotToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Telegram Bot API Token, risking unauthorized bot operations and message interception on Telegram.",
		RuleID:      "telegram-bot-api-token",

		Regex: utils2.GenerateSemiGenericRegex([]string{"telegr"}, "[0-9]{5,16}:(?-i:A)[a-z0-9_\\-]{34}", true),
		Keywords: []string{
			"telegr",
		},
	}

	// validate
	var (
		validToken = secrets.NewSecret(utils2.Numeric("8") + ":A" + utils2.AlphaNumericExtendedShort("34"))
		minToken   = secrets.NewSecret(utils2.Numeric("5") + ":A" + utils2.AlphaNumericExtendedShort("34"))
		maxToken   = secrets.NewSecret(utils2.Numeric("16") + ":A" + utils2.AlphaNumericExtendedShort("34"))
		// xsdWithToken = secrets.NewSecret(`<xsd:element name="AgencyIdentificationCode" type="` + Numeric("5") + `:A` + AlphaNumericExtendedShort("34") + `"/>`)
	)
	// variable assignment
	tps := utils2.GenerateSampleSecrets("telegram", validToken)
	// Token with min bot_id
	tps = append(tps, utils2.GenerateSampleSecrets("telegram", minToken)...)
	// Token with max bot_id
	tps = append(tps, utils2.GenerateSampleSecrets("telegram", maxToken)...)
	tps = append(tps,
		// URL containing token TODO add another url based rule
		// GenerateSampleSecret("url", "https://api.telegram.org/bot"+validToken+"/sendMessage"),
		// object constructor
		//TODO: `const bot = new Telegraf("`+validToken+`")`,
		// .env
		`TELEGRAM_API_TOKEN = `+validToken,
		// YAML
		`telegram bot: `+validToken,
		// Valid token in XSD document TODO separate rule for this
		// generateSampleSecret("telegram", xsdWithToken),
	)

	var (
		tooSmallToken                = secrets.NewSecret(utils2.Numeric("4") + ":A" + utils2.AlphaNumericExtendedShort("34"))
		tooBigToken                  = secrets.NewSecret(utils2.Numeric("17") + ":A" + utils2.AlphaNumericExtendedShort("34"))
		xsdAgencyIdentificationCode1 = secrets.NewSecret(`<xsd:element name="AgencyIdentificationCode" type="clm`+utils2.Numeric("5")+":AgencyIdentificationCodeContentType") + `"/>`
		xsdAgencyIdentificationCode2 = secrets.NewSecret(`token:"clm` + utils2.Numeric("5") + `:AgencyIdentificationCodeContentType"`)
		xsdAgencyIdentificationCode3 = secrets.NewSecret(`<xsd:element name="AgencyIdentificationCode" type="clm` + utils2.Numeric("8") + `:AgencyIdentificationCodeContentType"/>`)
		prefixedToken1               = secrets.NewSecret(`telegram_api_token = \"` + utils2.Numeric("8") + `:Ahello` + utils2.AlphaNumericExtendedShort("34") + `\"`)
		prefixedToken2               = secrets.NewSecret(`telegram_api_token = \"` + utils2.Numeric("8") + `:A-some-other-thing-` + utils2.AlphaNumericExtendedShort("34") + `\"`)
		prefixedToken3               = secrets.NewSecret(`telegram_api_token = \"` + utils2.Numeric("8") + `:A_` + utils2.AlphaNumericExtendedShort("34") + `\"`)
		suffixedToken1               = secrets.NewSecret(`telegram_api_token = \"` + utils2.Numeric("8") + `:A` + utils2.AlphaNumericExtendedShort("34") + `hello\"`)
		suffixedToken2               = secrets.NewSecret(`telegram_api_token = \"` + utils2.Numeric("8") + `:A` + utils2.AlphaNumericExtendedShort("34") + `-some-other-thing\"`)
		suffixedToken3               = secrets.NewSecret(`telegram_api_token = \"` + utils2.Numeric("8") + `:A_` + utils2.AlphaNumericExtendedShort("34") + `_\"`)
	)
	fps := []string{
		// Token with too small bot_id
		utils2.GenerateSampleSecret("telegram", tooSmallToken),
		// Token with too big bot_id
		utils2.GenerateSampleSecret("telegram", tooBigToken),
		// XSD file containing the string AgencyIdentificationCodeContentType
		utils2.GenerateSampleSecret("telegram", xsdAgencyIdentificationCode1),
		utils2.GenerateSampleSecret("telegram", xsdAgencyIdentificationCode2),
		utils2.GenerateSampleSecret("telegram", xsdAgencyIdentificationCode3),
		// Prefix and suffix variations that shouldn't match
		utils2.GenerateSampleSecret("telegram", prefixedToken1),
		utils2.GenerateSampleSecret("telegram", prefixedToken2),
		utils2.GenerateSampleSecret("telegram", prefixedToken3),
		utils2.GenerateSampleSecret("telegram", suffixedToken1),
		utils2.GenerateSampleSecret("telegram", suffixedToken2),
		utils2.GenerateSampleSecret("telegram", suffixedToken3),
	}

	return utils2.Validate(r, tps, fps)
}
