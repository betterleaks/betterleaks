package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "grafana-api-key",
	Confidence:  "high",
	Description: "Identified a Grafana API key, which could compromise monitoring dashboards and sensitive data analytics.",
	Regex:       Token(`eyJrIjoi[A-Za-z0-9+/]{40,380}={0,2}`),
	Keywords:    []string{"eyJrIjoi"},
	FilterExpr:  MinEntropy(3.0),
	Tests: []config.RuleTest{
		Match("grafana-api-key assignment", `grafana-api-keyToken = "eyJrIjoiVD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSYzNJ7pLcF6ubf1SxQeYd0TW"`, "eyJrIjoiVD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSYzNJ7pLcF6ubf1SxQeYd0TW"),
		Match("true positive 1", "Authorization: Bearer eyJrIjoiWHZiSWd5NzdCYUZnNUtibE8obUpESmE2bzJYNDRIc1UiLCJuIjoibXlrZXkiLCJpZCI6MX0=", "eyJrIjoiWHZiSWd5NzdCYUZnNUtibE8obUpESmE2bzJYNDRIc1UiLCJuIjoibXlrZXkiLCJpZCI6MX0="),
	},
})

var _ = Add(config.Rule{
	ID:           "grafana-cloud-api-token",
	Confidence:   "high",
	Description:  "Found a Grafana cloud API token, risking unauthorized access to cloud-based monitoring services and data exposure.",
	Regex:        Token(`glc_[A-Za-z0-9+/]{40,150}={0,2}`),
	Keywords:     []string{"glc_"},
	ValidateExpr: BearerGetValidationExpr("https://grafana.com/api/stack-regions", "true"),
	FilterExpr:   MinEntropy(3.0),
	Tests: []config.RuleTest{
		Match("grafana-cloud-api-token assignment", `grafana-cloud-api-tokenToken = "glc_VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxG"`, "glc_VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxG"),
		Match("true positive 1", `grafana-cloud-api-token_api_token = "glc_VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxG"`, "glc_VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxG"),
		Match("true positive 2", "loki_key: glc_eyJvIjoiNzQ0NTg3IiwibiI7InN0YWlrLTQ3NTgzMC1obC13cml0ZS1oYW5kc29uJG9raSIsImsiOiI4M2w3cmdYUlBoMTUyMW1lMU023nl5UDUiLCJtIjp7IOIiOiJ1cyJ9fQ==", "glc_eyJvIjoiNzQ0NTg3IiwibiI7InN0YWlrLTQ3NTgzMC1obC13cml0ZS1oYW5kc29uJG9raSIsImsiOiI4M2w3cmdYUlBoMTUyMW1lMU023nl5UDUiLCJtIjp7IOIiOiJ1cyJ9fQ=="),
		NoMatch("Low entropy", "glc_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
		NoMatch("false positive 1", `   API_KEY="glc_111111111111111111111111111111111111111111="`),
		NoMatch("Invalid", "static void GLC_CreateLightmapTextureArray(void);\nstatic void GLC_CreateLightmapTexturesIndividual(void);\n\nvoid GLC_UploadLightmap(int textureUnit, int lightmapnum);"),
		NoMatch("false positive 2", "// Alias models\nvoid GLC_StateBeginUnderwaterAliasModelCaustics(texture_ref base_texture, texture_ref caustics_texture)\n{"),
	},
})

var _ = Add(config.Rule{
	ID:          "grafana-service-account-token",
	Confidence:  "high",
	Description: "Discovered a Grafana service account token, posing a risk of compromised monitoring services and data integrity.",
	Regex:       Token(`glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}`),
	Keywords:    []string{"glsa_"},
	FilterExpr:  MinEntropy(3.0),
	Tests: []config.RuleTest{
		Match("grafana-service-account-token assignment", `grafana-service-account-tokenToken = "glsa_5fbbd6p84oe7ut4qrttebiwar77s63do_1f7b169c"`, "glsa_5fbbd6p84oe7ut4qrttebiwar77s63do_1f7b169c"),
		Match("true positive 1", "'Authorization': 'Bearer glsa_pITqMOBIfNH2KL4PkXJqmTyQl0D9QGxF_486f63e1'", "glsa_pITqMOBIfNH2KL4PkXJqmTyQl0D9QGxF_486f63e1"),
		NoMatch("false positive 1", "glsa_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_AAAAAAAA"),
	},
})
