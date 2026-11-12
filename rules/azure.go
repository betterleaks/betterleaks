package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "azure-tenant-id",
	Confidence:  "medium",
	Description: "Detected an Azure tenant ID, used as a component of Azure service principal validation.",
	Regex:       `(?i)\b(?:tenant[_\s.-]*(?:id)?|AZURE_TENANT_ID)\b(?s:.{0,24}?)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
	Keywords:    []string{"tenant"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) <= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "azure_tenant_id=72f988bf-86f1-41af-91ab-2d7cd011db47", "72f988bf-86f1-41af-91ab-2d7cd011db47"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "azure-client-id",
	Confidence:  "medium",
	Description: "Detected an Azure client ID, used as a component of Azure service principal validation.",
	Regex:       `(?i)\b(?:client[_\s.-]*id|AZURE_CLIENT_ID)\b(?s:.{0,24}?)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
	Keywords:    []string{"client"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) <= 2.5`,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "azure_client_id=f47ac10b-58cc-4372-a567-0e02b2c3d479", "f47ac10b-58cc-4372-a567-0e02b2c3d479"),
	},
})

// References:
// - https://learn.microsoft.com/en-us/microsoft-365/compliance/sit-defn-azure-ad-client-secret
// - https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app#add-credentials
var _ = rulebuilder.Add(config.Rule{
	ID:          "azure-ad-client-secret",
	Confidence:  "high",
	Description: "Azure AD Client Secret",
	// After inspecting dozens of secrets, I'm fairly confident that they start with `xxx\dQ~`.
	// However, this may not be (entirely) true, and this rule might need to be further refined in the future.
	// Furthermore, it's possible that secrets have a checksum that could be used to further constrain this pattern.
	Regex: `(?:^|[\\'"\x60\s>=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\'"\x60\s<),])`, // wtf, Go? https://github.com/golang/go/issues/18221
	// The regex requires a digit immediately before `Q~`, so enumerate
	// the ten digit-prefixed forms instead of the much looser `q~`.
	Keywords: []string{
		"0q~", "1q~", "2q~", "3q~", "4q~",
		"5q~", "6q~", "7q~", "8q~", "9q~",
	},
	Components: []config.Component{
		{RuleID: "azure-tenant-id", Within: "8L"},
		{RuleID: "azure-client-id", Within: "8L"},
	},
	ValidateExpr: `let r = azure.validateServicePrincipal((components["azure-tenant-id"]?.secret ?? ""), (components["azure-client-id"]?.secret ?? ""), finding["secret"]); r.status == 200 ? {
  "result": "valid",
  "metadata": {"tenant_id": r.tenant_id, "client_id": r.client_id}
} : r.status in [400, 401, 403, 404] ? {
  "result": "invalid",
  "metadata": {"error_code": r.error_code, "error_message": r.error_message}
} : validate.unknown(r)
`,
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "client_secret=bP88Q~rcBcYjzzOhg1Hnn76Wm3jGgakZiZ.8vMgR\nazure_tenant_id=72f988bf-86f1-41af-91ab-2d7cd011db47\nazure_client_id=f47ac10b-58cc-4372-a567-0e02b2c3d479",
			Expect: []config.ExpectedFinding{
				{Secret: "bP88Q~rcBcYjzzOhg1Hnn76Wm3jGgakZiZ.8vMgR", ComponentSets: []map[string]string{{"azure-client-id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "azure-tenant-id": "72f988bf-86f1-41af-91ab-2d7cd011db47"}}},
			},
		},
		{
			Name:  "true positive 2",
			Input: "client_secret=bP88Q~rcBcYjzzOhg1Hnn76Wm3jGgakZiZ.8vMgR\n\nazure_tenant_id=72f988bf-86f1-41af-91ab-2d7cd011db47\nazure_client_id=f47ac10b-58cc-4372-a567-0e02b2c3d479",
			Expect: []config.ExpectedFinding{
				{Secret: "bP88Q~rcBcYjzzOhg1Hnn76Wm3jGgakZiZ.8vMgR", ComponentSets: []map[string]string{{"azure-client-id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "azure-tenant-id": "72f988bf-86f1-41af-91ab-2d7cd011db47"}}},
			},
		},
		{
			Name:  "true positive 3",
			Input: "client_secret: .IQ8Q~79R7TOWOspFnWcEG-dYt4KXqFqxK16cxr\nazure_tenant_id=72f988bf-86f1-41af-91ab-2d7cd011db47\nazure_client_id=f47ac10b-58cc-4372-a567-0e02b2c3d479",
			Expect: []config.ExpectedFinding{
				{Secret: ".IQ8Q~79R7TOWOspFnWcEG-dYt4KXqFqxK16cxr", ComponentSets: []map[string]string{{"azure-client-id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "azure-tenant-id": "72f988bf-86f1-41af-91ab-2d7cd011db47"}}},
			},
		},
		{
			Name:  "true positive 4",
			Input: "AUTH_CLIENTSECRET = _V28Q~IC8qxmlWNpHuDm34JlbKv9LXV5MvUR3a-P\nazure_tenant_id=72f988bf-86f1-41af-91ab-2d7cd011db47\nazure_client_id=f47ac10b-58cc-4372-a567-0e02b2c3d479",
			Expect: []config.ExpectedFinding{
				{Secret: "_V28Q~IC8qxmlWNpHuDm34JlbKv9LXV5MvUR3a-P", ComponentSets: []map[string]string{{"azure-client-id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "azure-tenant-id": "72f988bf-86f1-41af-91ab-2d7cd011db47"}}},
			},
		},
		{
			Name:  "true positive 5",
			Input: "<value xsi:type=\"xsd:string\">~Gg8Q~nVhlLi2vpg_nXBGqFsbGK-t~Hus1JmTa0y</value>\nazure_tenant_id=72f988bf-86f1-41af-91ab-2d7cd011db47\nazure_client_id=f47ac10b-58cc-4372-a567-0e02b2c3d479",
			Expect: []config.ExpectedFinding{
				{Secret: "~Gg8Q~nVhlLi2vpg_nXBGqFsbGK-t~Hus1JmTa0y", ComponentSets: []map[string]string{{"azure-client-id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "azure-tenant-id": "72f988bf-86f1-41af-91ab-2d7cd011db47"}}},
			},
		},
		{
			Name:  "true positive 6",
			Input: "\"CLIENT_SECRET\": \"YYz7Q~Sudoqwap1PnzEBA3zqBK~i5uesDIv.C\"\nazure_tenant_id=72f988bf-86f1-41af-91ab-2d7cd011db47\nazure_client_id=f47ac10b-58cc-4372-a567-0e02b2c3d479",
			Expect: []config.ExpectedFinding{
				{Secret: "YYz7Q~Sudoqwap1PnzEBA3zqBK~i5uesDIv.C", ComponentSets: []map[string]string{{"azure-client-id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "azure-tenant-id": "72f988bf-86f1-41af-91ab-2d7cd011db47"}}},
			},
		},
		{
			Name:  "true positive 7",
			Input: "Set-PSUAuthenticationMethod -Type 'OpenIDConnect' -CallbackPath '/auth/oidc' -ClientId 'fake' -ClientSecret '2Vq7Q~q5VgKljZ7cb3.0sp0Apz.vOjRIPyeTr'\nazure_tenant_id=72f988bf-86f1-41af-91ab-2d7cd011db47\nazure_client_id=f47ac10b-58cc-4372-a567-0e02b2c3d479",
			Expect: []config.ExpectedFinding{
				{Secret: "2Vq7Q~q5VgKljZ7cb3.0sp0Apz.vOjRIPyeTr", ComponentSets: []map[string]string{{"azure-client-id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "azure-tenant-id": "72f988bf-86f1-41af-91ab-2d7cd011db47"}}},
			},
		},
		{
			Name:  "true positive 8",
			Input: "client-secret: \"t028Q~-aLbmQuinnZtzbgtlEAYstnBWEmGPAoBm\"\nazure_tenant_id=72f988bf-86f1-41af-91ab-2d7cd011db47\nazure_client_id=f47ac10b-58cc-4372-a567-0e02b2c3d479",
			Expect: []config.ExpectedFinding{
				{Secret: "t028Q~-aLbmQuinnZtzbgtlEAYstnBWEmGPAoBm", ComponentSets: []map[string]string{{"azure-client-id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "azure-tenant-id": "72f988bf-86f1-41af-91ab-2d7cd011db47"}}},
			},
		},
		{
			Name:  "true positive 9",
			Input: "\"cas.authn.azure-active-directory.client-secret=qHF8Q~PCM5HhMoyTFc5TYEomnzR6Kim9UJhe8a.P\",\nazure_tenant_id=72f988bf-86f1-41af-91ab-2d7cd011db47\nazure_client_id=f47ac10b-58cc-4372-a567-0e02b2c3d479",
			Expect: []config.ExpectedFinding{
				{Secret: "qHF8Q~PCM5HhMoyTFc5TYEomnzR6Kim9UJhe8a.P", ComponentSets: []map[string]string{{"azure-client-id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "azure-tenant-id": "72f988bf-86f1-41af-91ab-2d7cd011db47"}}},
			},
		},
		{
			Name:  "true positive 10",
			Input: "\"line\": \"client_srt = \\\"qpF8Q~PCM5MhMoyTFc5TYEomnYRUKim9UJhe8a2P\\\";\",\nazure_tenant_id=72f988bf-86f1-41af-91ab-2d7cd011db47\nazure_client_id=f47ac10b-58cc-4372-a567-0e02b2c3d479",
			Expect: []config.ExpectedFinding{
				{Secret: "qpF8Q~PCM5MhMoyTFc5TYEomnYRUKim9UJhe8a2P", ComponentSets: []map[string]string{{"azure-client-id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "azure-tenant-id": "72f988bf-86f1-41af-91ab-2d7cd011db47"}}},
			},
		},
		{
			Name:  "true positive 11",
			Input: "\"client_secret\":       acctest.Representation{RepType: acctest.Required, Create: 'dO29Q~F5-VwnW.lZdd11xFF_t5NAXCaGwDl9NbT1'},\nazure_tenant_id=72f988bf-86f1-41af-91ab-2d7cd011db47\nazure_client_id=f47ac10b-58cc-4372-a567-0e02b2c3d479",
			Expect: []config.ExpectedFinding{
				{Secret: "dO29Q~F5-VwnW.lZdd11xFF_t5NAXCaGwDl9NbT1", ComponentSets: []map[string]string{{"azure-client-id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "azure-tenant-id": "72f988bf-86f1-41af-91ab-2d7cd011db47"}}},
			},
		},
		{
			Name:  "true positive 12",
			Input: "Example= GN.7Q~4AkLZBNEbz4Jxlm~O5G6SsyFxYg6zMR\nazure_tenant_id=72f988bf-86f1-41af-91ab-2d7cd011db47\nazure_client_id=f47ac10b-58cc-4372-a567-0e02b2c3d479",
			Expect: []config.ExpectedFinding{
				{Secret: "GN.7Q~4AkLZBNEbz4Jxlm~O5G6SsyFxYg6zMR", ComponentSets: []map[string]string{{"azure-client-id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "azure-tenant-id": "72f988bf-86f1-41af-91ab-2d7cd011db47"}}},
			},
		},
		{
			Name:  "true positive 13",
			Input: "\"the_value\": \"QtT8Q~9C-_Ij~RouHVpD2Tuf3oHWGh.DQ3kcjbAn\"\nazure_tenant_id=72f988bf-86f1-41af-91ab-2d7cd011db47\nazure_client_id=f47ac10b-58cc-4372-a567-0e02b2c3d479",
			Expect: []config.ExpectedFinding{
				{Secret: "QtT8Q~9C-_Ij~RouHVpD2Tuf3oHWGh.DQ3kcjbAn", ComponentSets: []map[string]string{{"azure-client-id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "azure-tenant-id": "72f988bf-86f1-41af-91ab-2d7cd011db47"}}},
			},
		},
		{
			Name:  "true positive 14",
			Input: "QtT8Q~9C-_Ij~RouHVpD2Tuf3oHWGh.DQ3kcjbAn\nazure_tenant_id=72f988bf-86f1-41af-91ab-2d7cd011db47\nazure_client_id=f47ac10b-58cc-4372-a567-0e02b2c3d479",
			Expect: []config.ExpectedFinding{
				{Secret: "QtT8Q~9C-_Ij~RouHVpD2Tuf3oHWGh.DQ3kcjbAn", ComponentSets: []map[string]string{{"azure-client-id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "azure-tenant-id": "72f988bf-86f1-41af-91ab-2d7cd011db47"}}},
			},
		},
		{
			Name:  "true positive 15",
			Input: "(use the client secret: QtT8Q~9C-_Ij~RouHVpD2Tuf3oHWGh.DQ3kcjbAn)\nazure_tenant_id=72f988bf-86f1-41af-91ab-2d7cd011db47\nazure_client_id=f47ac10b-58cc-4372-a567-0e02b2c3d479",
			Expect: []config.ExpectedFinding{
				{Secret: "QtT8Q~9C-_Ij~RouHVpD2Tuf3oHWGh.DQ3kcjbAn", ComponentSets: []map[string]string{{"azure-client-id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "azure-tenant-id": "72f988bf-86f1-41af-91ab-2d7cd011db47"}}},
			},
		},
		{
			Name:  "true positive 16",
			Input: "(QtT8Q~9C-_Ij~RouHVpD2Tuf3oHWGh.DQ3kcjbAn)\nazure_tenant_id=72f988bf-86f1-41af-91ab-2d7cd011db47\nazure_client_id=f47ac10b-58cc-4372-a567-0e02b2c3d479",
			Expect: []config.ExpectedFinding{
				{Secret: "QtT8Q~9C-_Ij~RouHVpD2Tuf3oHWGh.DQ3kcjbAn", ComponentSets: []map[string]string{{"azure-client-id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "azure-tenant-id": "72f988bf-86f1-41af-91ab-2d7cd011db47"}}},
			},
		},
		{
			Name:  "true positive 17",
			Input: "\\\"pass\\\": \\\"Zj_1Q~LgoiBj5lQ4Oqp9Wlm3c_c-U87qkQM7q\nazure_tenant_id=72f988bf-86f1-41af-91ab-2d7cd011db47\nazure_client_id=f47ac10b-58cc-4372-a567-0e02b2c3d479",
			Expect: []config.ExpectedFinding{
				{Secret: "Zj_1Q~LgoiBj5lQ4Oqp9Wlm3c_c-U87qkQM7q", ComponentSets: []map[string]string{{"azure-client-id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "azure-tenant-id": "72f988bf-86f1-41af-91ab-2d7cd011db47"}}},
			},
		},
		rulebuilder.NoMatch("false positive 1", "// CloudFront-Signature: Ixn4bF1LLrLcB8XG-t5bZbIB0vfwSF2s4gkef~PcNBdx73MVvZD3v8DZ5GzcqNrybMiqdYJY5KqK6vTsf5JXDgwFFz-h98wdsbV-izcuonPdzMHp4Ay4qyXM6Ed5jB9dUWYGwMkA6rsWXpftfX8xmk4tG1LwFuJV6nAsx4cfpuKwo4vU2Hyr2-fkA7MZG8AHkpDdVUnjm1q-Re9HdG0nCq-2lnBAdOchBpJt37narOj-Zg6cbx~6rzQLVQd8XIv-Bn7VTc1tkBAJVtGOHb0Q~PLzSRmtNGYTnpL0z~gp3tq8lhZc2HuvJW5-tZaYP9yufeIzk5bqsT6DT4iDuclKKw__, , , false"),
		rulebuilder.NoMatch("false positive 2", `+ "<Trust Comment=\"\" Identity=\"USK@u2vn3Lh6Kte2-TgBSNKorbsKkuAt34ckoLmgx0ndXO0,4~q8Q~3wIHjX9DT0yCNfQmr9oxmYrDZoQVLOdNg~yk0,AQACAAE/WebOfTrustRC2/2\" Value=\"100\"/>"`),
		rulebuilder.NoMatch("false positive 3", "client_secret=bP88Q~xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "azure-storage-account-name",
	Confidence:  "medium",
	Description: "Detected an Azure Storage account name, used as a component of Azure Storage key validation.",
	Regex:       `(?i)(?:\bAccountName\s*=\s*([a-z0-9]{3,24})\b|https://([a-z0-9]{3,24})\.blob\.core\.windows\.net\b|\b(?:azure[_\s.-]*storage[_\s.-]*(?:account[_\s.-]*)?name|storage[_\s.-]*account[_\s.-]*name)\b(?s:.{0,24}?)([a-z0-9]{3,24})\b)`,
	Keywords:    []string{"accountname", "blob.core.windows.net", "storage"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) <= 1.5`,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("true positive 1", "AccountName=mystorageaccount;AccountKey=VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSYzNJ7pLcF6ubf1SxQeYd0TW9ceqba75woTt/R7f==", "mystorageaccount"),
		rulebuilder.MatchComponent("true positive 2", "https://prodlogs.blob.core.windows.net/container", "prodlogs"),
		rulebuilder.MatchComponent("true positive 3", "AZURE_STORAGE_ACCOUNT_NAME=prodblob2024", "prodblob2024"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "azure-storage-account-key",
	Confidence:  "high",
	Description: "Detected an Azure Storage account key.",
	Regex:       `(?i)\b(?:AccountKey|(?:azure[_\s.-]*)?(?:storage[_\s.-]*)?(?:account[_\s.-]*)?(?:access[_\s.-]*)?key)\b(?s:.{0,24}?)([A-Za-z0-9+/]{86}==)`,
	Keywords:    []string{"accountkey", "storage", "accesskey", "access_key", "access-key"},
	Components: []config.Component{
		{RuleID: "azure-storage-account-name", Within: "8L"},
	},
	ValidateExpr: `let r = azure.validateStorage((components["azure-storage-account-name"]?.secret ?? ""), finding["secret"]); r.status == 200 ? {
  "result": "valid",
  "metadata": {"account": r.account, "containers": r.containers}
} : r.status in [400, 401, 403, 404] ? {
  "result": "invalid",
  "metadata": {"error_code": r.error_code, "error_message": r.error_message}
} : validate.unknown(r)
`,
	FilterExpr: `entropy(finding["secret"]) <= 4.0`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "AccountName=mystorageaccount;AccountKey=VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSYzNJ7pLcF6ubf1SxQeYd0TW9ceqba75woTt/R7f==",
			Expect: []config.ExpectedFinding{
				{Secret: "VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSYzNJ7pLcF6ubf1SxQeYd0TW9ceqba75woTt/R7f==", ComponentSets: []map[string]string{{"azure-storage-account-name": "mystorageaccount"}}},
			},
		},
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "azure-app-configuration-connection-string",
	Confidence:  "high",
	Description: "Detected an Azure App Configuration connection string.",
	Regex:       `(?i)Endpoint=(?P<azure_appconfig_endpoint>https://[a-z0-9-]+\.azconfig\.io);Id=(?P<azure_appconfig_id>[^;\s'"]{4,80});Secret=([A-Za-z0-9+/]{36,100}={0,2})`,
	ValueGroup:  3,
	Keywords:    []string{"azconfig.io", "endpoint=", "secret="},
	ValidateExpr: `let r = azure.validateAppConfig(
  finding["captures"]?.azure_appconfig_endpoint ?? "",
  finding["captures"]?.azure_appconfig_id ?? "",
  finding["secret"]
); r.status == 200 ? {
  "result": "valid",
  "metadata": {"endpoint": r.endpoint, "id": r.id}
} : r.status in [400, 401, 403, 404] ? {
  "result": "invalid",
  "metadata": {"error_code": r.error_code, "error_message": r.error_message}
} : validate.unknown(r)
`,
	FilterExpr: `entropy(finding["secret"]) <= 3.5`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "Endpoint=https://foo-nonprod-appconfig.azconfig.io;Id=ABCD-E6-s0:tl6ABcdefGHi7kLMno/p;Secret=VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81=",
			Expect: []config.ExpectedFinding{
				{Secret: "VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81=", Captures: map[string]string{"azure_appconfig_endpoint": "https://foo-nonprod-appconfig.azconfig.io", "azure_appconfig_id": "ABCD-E6-s0:tl6ABcdefGHi7kLMno/p"}},
			},
		},
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "azure-servicebus-connection-string",
	Confidence:  "high",
	Description: "Detected an Azure Service Bus or Event Hub shared access connection string.",
	Regex:       `(?i)(Endpoint=sb://[a-z0-9-]+\.servicebus\.windows\.net/;SharedAccessKeyName=[^;=\s'"]{1,128};SharedAccessKey=[A-Za-z0-9+/]{32,100}={0,2}(?:;EntityPath=[^;\s'"]{1,128})?)`,
	Keywords:    []string{"endpoint=sb://", "sharedaccesskey"},
	ValidateExpr: `let r = azure.validateServiceBusSAS(finding["secret"]); r.status in [200, 201, 202, 204] ? {
  "result": "valid",
  "metadata": {"host": r.host, "entity_path": r.entity_path}
} : r.status in [400, 401, 403, 404] ? {
  "result": "invalid",
  "metadata": {"error_code": r.error_code, "error_message": r.error_message}
} : validate.unknown(r)
`,
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		rulebuilder.Match("bare secret", "Endpoint=sb://orders-prod.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSYzNJ7pLcF;EntityPath=orders", "Endpoint=sb://orders-prod.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=VD5v/4tg6Y4jWlMO9JZWDOcGzfjsqrpsPDZAdrxGBG81lHSYzNJ7pLcF;EntityPath=orders"),
	},
})
