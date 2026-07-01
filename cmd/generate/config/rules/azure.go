package rules

import (
	"fmt"

	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func AzureTenantID() *config.Rule {
	r := config.Rule{
		RuleID:      "azure-tenant-id",
		Description: "Detected an Azure tenant ID, used as a component of Azure service principal validation.",
		Regex:       regexp.MustCompile(`(?i)\b(?:tenant[_\s.-]*(?:id)?|AZURE_TENANT_ID)\b(?s:.{0,24}?)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
		Keywords:    []string{"tenant"},
		SkipReport:  true,
		Filter:      `entropy(finding["secret"]) <= 2.5`,
	}
	return utils.Validate(r, []string{`azure_tenant_id=72f988bf-86f1-41af-91ab-2d7cd011db47`}, nil)
}

func AzureClientID() *config.Rule {
	r := config.Rule{
		RuleID:      "azure-client-id",
		Description: "Detected an Azure client ID, used as a component of Azure service principal validation.",
		Regex:       regexp.MustCompile(`(?i)\b(?:client[_\s.-]*id|AZURE_CLIENT_ID)\b(?s:.{0,24}?)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`),
		Keywords:    []string{"client"},
		SkipReport:  true,
		Filter:      `entropy(finding["secret"]) <= 2.5`,
	}
	return utils.Validate(r, []string{`azure_client_id=f47ac10b-58cc-4372-a567-0e02b2c3d479`}, nil)
}

// References:
// - https://learn.microsoft.com/en-us/microsoft-365/compliance/sit-defn-azure-ad-client-secret
// - https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app#add-credentials
func AzureActiveDirectoryClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "azure-ad-client-secret",
		Description: "Azure AD Client Secret",
		// After inspecting dozens of secrets, I'm fairly confident that they start with `xxx\dQ~`.
		// However, this may not be (entirely) true, and this rule might need to be further refined in the future.
		// Furthermore, it's possible that secrets have a checksum that could be used to further constrain this pattern.
		Regex: regexp.MustCompile(`(?:^|[\\'"\x60\s>=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\'"\x60\s<),])`), // wtf, Go? https://github.com/golang/go/issues/18221
		// The regex requires a digit immediately before `Q~`, so enumerate
		// the ten digit-prefixed forms instead of the much looser `q~`.
		Keywords: []string{
			"0q~", "1q~", "2q~", "3q~", "4q~",
			"5q~", "6q~", "7q~", "8q~", "9q~",
		},
		RequiredRules: []*config.Required{
			{RuleID: "azure-tenant-id", WithinLines: utils.Ptr(8)},
			{RuleID: "azure-client-id", WithinLines: utils.Ptr(8)},
		},
		ValidateExpr: `let r = azure.validateServicePrincipal(captures["azure-tenant-id"], captures["azure-client-id"], finding["secret"]); r.status == 200 ? {
  "result": "valid",
  "tenant_id": r.tenant_id,
  "client_id": r.client_id
} : r.status in [400, 401, 403, 404] ? {
  "result": "invalid",
  "error_code": r.error_code,
  "error_message": r.error_message
} : validate.unknown(r)
`,
		Filter: `entropy(finding["secret"]) <= 3.0`,
	}

	// validate
	tps := []string{
		`client_secret=bP88Q~rcBcYjzzOhg1Hnn76Wm3jGgakZiZ.8vMgR`,
		`client_secret=bP88Q~rcBcYjzzOhg1Hnn76Wm3jGgakZiZ.8vMgR
`,
		`client_secret: .IQ8Q~79R7TOWOspFnWcEG-dYt4KXqFqxK16cxr`,
		`AUTH_CLIENTSECRET = _V28Q~IC8qxmlWNpHuDm34JlbKv9LXV5MvUR3a-P`,
		`<value xsi:type="xsd:string">~Gg8Q~nVhlLi2vpg_nXBGqFsbGK-t~Hus1JmTa0y</value>`,
		`"CLIENT_SECRET": "YYz7Q~Sudoqwap1PnzEBA3zqBK~i5uesDIv.C"`,
		`Set-PSUAuthenticationMethod -Type 'OpenIDConnect' -CallbackPath '/auth/oidc' -ClientId 'fake' -ClientSecret '2Vq7Q~q5VgKljZ7cb3.0sp0Apz.vOjRIPyeTr'`,
		`client-secret: "t028Q~-aLbmQuinnZtzbgtlEAYstnBWEmGPAoBm"`,
		`"cas.authn.azure-active-directory.client-secret=qHF8Q~PCM5HhMoyTFc5TYEomnzR6Kim9UJhe8a.P",`,
		`"line": "client_srt = \"qpF8Q~PCM5MhMoyTFc5TYEomnYRUKim9UJhe8a2P\";",`,
		`"client_secret":       acctest.Representation{RepType: acctest.Required, Create: 'dO29Q~F5-VwnW.lZdd11xFF_t5NAXCaGwDl9NbT1'},`,
		`Example= GN.7Q~4AkLZBNEbz4Jxlm~O5G6SsyFxYg6zMR`,
		`"the_value": "QtT8Q~9C-_Ij~RouHVpD2Tuf3oHWGh.DQ3kcjbAn"`,
		`QtT8Q~9C-_Ij~RouHVpD2Tuf3oHWGh.DQ3kcjbAn`,
		`(use the client secret: QtT8Q~9C-_Ij~RouHVpD2Tuf3oHWGh.DQ3kcjbAn)`,
		`(QtT8Q~9C-_Ij~RouHVpD2Tuf3oHWGh.DQ3kcjbAn)`,
		`\"pass\": \"` + fmt.Sprintf("%s%sQ~%s", secrets.NewSecret(`[\w~.]{3}`), secrets.NewSecret(utils.Numeric("1")), secrets.NewSecretWithEntropy(`[\w~.-]{31,34}`, 3)),
	}
	fps := []string{
		`// CloudFront-Signature: Ixn4bF1LLrLcB8XG-t5bZbIB0vfwSF2s4gkef~PcNBdx73MVvZD3v8DZ5GzcqNrybMiqdYJY5KqK6vTsf5JXDgwFFz-h98wdsbV-izcuonPdzMHp4Ay4qyXM6Ed5jB9dUWYGwMkA6rsWXpftfX8xmk4tG1LwFuJV6nAsx4cfpuKwo4vU2Hyr2-fkA7MZG8AHkpDdVUnjm1q-Re9HdG0nCq-2lnBAdOchBpJt37narOj-Zg6cbx~6rzQLVQd8XIv-Bn7VTc1tkBAJVtGOHb0Q~PLzSRmtNGYTnpL0z~gp3tq8lhZc2HuvJW5-tZaYP9yufeIzk5bqsT6DT4iDuclKKw__, , , false`,
		`+ "<Trust Comment=\"\" Identity=\"USK@u2vn3Lh6Kte2-TgBSNKorbsKkuAt34ckoLmgx0ndXO0,4~q8Q~3wIHjX9DT0yCNfQmr9oxmYrDZoQVLOdNg~yk0,AQACAAE/WebOfTrustRC2/2\" Value=\"100\"/>"`,
		`client_secret=bP88Q~xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}
	return utils.Validate(r, tps, fps)
}

func AzureStorageAccountName() *config.Rule {
	r := config.Rule{
		RuleID:      "azure-storage-account-name",
		Description: "Detected an Azure Storage account name, used as a component of Azure Storage key validation.",
		Regex:       regexp.MustCompile(`(?i)(?:\bAccountName\s*=\s*([a-z0-9]{3,24})\b|https://([a-z0-9]{3,24})\.blob\.core\.windows\.net\b|\b(?:azure[_\s.-]*storage[_\s.-]*(?:account[_\s.-]*)?name|storage[_\s.-]*account[_\s.-]*name)\b(?s:.{0,24}?)([a-z0-9]{3,24})\b)`),
		Keywords:    []string{"AccountName", "blob.core.windows.net", "storage"},
		SkipReport:  true,
		Filter:      `entropy(finding["secret"]) <= 1.5`,
	}
	storageKey := azureStorageKeySample()
	return utils.Validate(r, []string{
		`AccountName=mystorageaccount;AccountKey=` + storageKey,
		`https://prodlogs.blob.core.windows.net/container`,
		`AZURE_STORAGE_ACCOUNT_NAME=prodblob2024`,
	}, nil)
}

func AzureStorageAccountKey() *config.Rule {
	r := config.Rule{
		RuleID:      "azure-storage-account-key",
		Description: "Detected an Azure Storage account key.",
		Regex:       regexp.MustCompile(`(?i)\b(?:AccountKey|(?:azure[_\s.-]*)?(?:storage[_\s.-]*)?(?:account[_\s.-]*)?(?:access[_\s.-]*)?key)\b(?s:.{0,24}?)([A-Za-z0-9+/]{86}==)`),
		Keywords:    []string{"AccountKey", "storage", "key"},
		RequiredRules: []*config.Required{
			{RuleID: "azure-storage-account-name", WithinLines: utils.Ptr(8)},
		},
		ValidateExpr: `let r = azure.validateStorage(captures["azure-storage-account-name"], finding["secret"]); r.status == 200 ? {
  "result": "valid",
  "account": r.account,
  "containers": r.containers
} : r.status in [400, 401, 403, 404] ? {
  "result": "invalid",
  "error_code": r.error_code,
  "error_message": r.error_message
} : validate.unknown(r)
`,
		Filter: `entropy(finding["secret"]) <= 4.0`,
	}
	return utils.Validate(r, []string{`AccountName=mystorageaccount;AccountKey=` + azureStorageKeySample()}, nil)
}

func AzureAppConfigurationConnectionString() *config.Rule {
	r := config.Rule{
		RuleID:      "azure-app-configuration-connection-string",
		Description: "Detected an Azure App Configuration connection string.",
		Regex:       regexp.MustCompile(`(?i)Endpoint=(?P<azure_appconfig_endpoint>https://[a-z0-9-]+\.azconfig\.io);Id=(?P<azure_appconfig_id>[^;\s'"]{4,80});Secret=([A-Za-z0-9+/]{36,100}={0,2})`),
		SecretGroup: 3,
		Keywords:    []string{"azconfig.io", "Endpoint=", "Secret="},
		ValidateExpr: `let r = azure.validateAppConfig(captures["azure_appconfig_endpoint"], captures["azure_appconfig_id"], finding["secret"]); r.status == 200 ? {
  "result": "valid",
  "endpoint": r.endpoint,
  "id": r.id
} : r.status in [400, 401, 403, 404] ? {
  "result": "invalid",
  "error_code": r.error_code,
  "error_message": r.error_message
} : validate.unknown(r)
`,
		Filter: `entropy(finding["secret"]) <= 3.5`,
	}
	return utils.Validate(r, []string{
		`Endpoint=https://foo-nonprod-appconfig.azconfig.io;Id=ABCD-E6-s0:tl6ABcdefGHi7kLMno/p;Secret=` + secrets.NewSecretWithEntropy(`[A-Za-z0-9+/]{44}=`, 3.5),
	}, nil)
}

func AzureServiceBusConnectionString() *config.Rule {
	r := config.Rule{
		RuleID:      "azure-servicebus-connection-string",
		Description: "Detected an Azure Service Bus or Event Hub shared access connection string.",
		Regex:       regexp.MustCompile(`(?i)(Endpoint=sb://[a-z0-9-]+\.servicebus\.windows\.net/;SharedAccessKeyName=[^;=\s'"]{1,128};SharedAccessKey=[A-Za-z0-9+/]{32,100}={0,2}(?:;EntityPath=[^;\s'"]{1,128})?)`),
		Keywords:    []string{"Endpoint=sb://", "SharedAccessKey"},
		ValidateExpr: `let r = azure.validateServiceBusSAS(finding["secret"]); r.status in [200, 201, 202, 204] ? {
  "result": "valid",
  "host": r.host,
  "entity_path": r.entity_path
} : r.status in [400, 401, 403, 404] ? {
  "result": "invalid",
  "error_code": r.error_code,
  "error_message": r.error_message
} : validate.unknown(r)
`,
		Filter: `entropy(finding["secret"]) <= 3.0`,
	}
	return utils.Validate(r, []string{`Endpoint=sb://orders-prod.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=` + secrets.NewSecretWithEntropy(`[A-Za-z0-9+/]{56}`, 3.5) + `;EntityPath=orders`}, nil)
}

func azureStorageKeySample() string {
	return secrets.NewSecretWithEntropy(`[A-Za-z0-9+/]{86}`, 4) + "=="
}
