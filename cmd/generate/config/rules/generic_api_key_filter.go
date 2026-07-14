package rules

import (
	"strconv"
	"strings"
)

const genericAPIKeyMatchFilter = `(?i)(?:access(?:ibility|or)|access[_.-]?id|random[_.-]?access|api[_.-]?(?:id|name|version)|rapid|capital|[a-z0-9-]*?api[a-z0-9-]*?:jar:|author|X-MS-Exchange-Organization-Auth|Authentication-Results|(?:credentials?[_.-]?id|withCredentials)|(?:bucket|foreign|hot|idx|natural|primary|pub(?:lic)?|schema|sequence)[_.-]?key|(?:turkey)|key[_.-]?(?:alias|board|code|frame|id|length|mesh|name|pair|press(?:ed)?|ring|selector|signature|size|stone|storetype|word|up|down|left|right)|key[_.-]?vault[_.-]?(?:id|name)|keyVaultToStoreSecrets|key(?:store|tab)[_.-]?(?:file|path)|issuerkeyhash|(?-i:[DdMm]onkey|[DM]ONKEY)|keying|(?:secret)[_.-]?(?:length|name|size)|UserSecretsId|(?:csrf)[_.-]?token|(?:io\.jsonwebtoken[ \t]?:[ \t]?[\w-]+)|(?:api|credentials|token)[_.-]?(?:endpoint|ur[il])|public[_.-]?token|(?:key|token)[_.-]?file|(?-i:(?:[A-Z_]+=\n[A-Z_]+=|[a-z_]+=\n[a-z_]+=)(?:\n|\z))|(?-i:(?:[A-Z.]+=\n[A-Z.]+=|[a-z.]+=\n[a-z.]+=)(?:\n|\z)))`

var genericAPIKeyFilter = buildGenericAPIKeyFilter()

func buildGenericAPIKeyFilter() string {
	return `matchesAny(finding["secret"], [` + "`^[a-zA-Z_.-]+$`" + `])
|| (containsAny(finding["secret"], ` + exprStringList(DefaultStopWords) + `) || filter.matchesAnyNearMatch(finding, [` + "`" + genericAPIKeyMatchFilter + "`" + `], 50, 0, true))
|| matchesAny(finding["line"], [
  ` + "`--mount=type=secret,`" + `,
  ` + "`import[ \\t]+{[ \\t\\w,]+}[ \\t]+from[ \\t]+['\"][^'\"]+['\"]`" + `
])
|| (matchesAny(get(attributes, "path", ""), [
  ` + "`\\.bb$`" + `,
  ` + "`\\.bbappend$`" + `,
  ` + "`\\.bbclass$`" + `,
  ` + "`\\.inc$`" + `
]) && matchesAny(finding["line"], [
  ` + "`LICENSE[^=]*=\\s*\"[^\"]+`" + `,
  ` + "`LIC_FILES_CHKSUM[^=]*=\\s*\"[^\"]+`" + `,
  ` + "`SRC[^=]*=\\s*\"[a-zA-Z0-9]+`" + `
]))` + buildTestAndPublicAPIFilters()
}

// testAndPublicAPIFilter filters out a finding whose secret matches regex. When
// keywords is non-empty, the secret is only filtered if one of the keywords
// also appears nearby on the finding's line.
type testAndPublicAPIFilter struct {
	regex    string
	keywords []string
}

const uuidHex = `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`

// testAndPublicAPIFilters is a denylist of test and public API key patterns.
var testAndPublicAPIFilters = []testAndPublicAPIFilter{
	// Regex Only
	{regex: `sb_publishable_[A-Za-z0-9_-]{31}`},                         // Supabase Publishable Key
	{regex: `0x4AAAAAA[A-Za-z0-9_-]{15}`},                               // Cloudflare Turnstile Site Key
	{regex: `FCM[a-zA-Z0-9]{13}`},                                       // Friendly Captcha Site Key
	{regex: `ysc1_[A-Za-z0-9_-]{48}`},                                   // Yandex SmartCaptcha Site Key
	{regex: `phc_[A-Za-z0-9_-]{43,44}`},                                 // Posthog Project API Key
	{regex: `APP_USR-` + uuidHex},                                       // Mercado Pago Production Public Key
	{regex: `access-(sandbox|development)-` + uuidHex},                  // Plaid Sandbox/Development Access Token
	{regex: `asset-report-(sandbox|development)-` + uuidHex},            // Plaid Sandbox/Development Asset Report Token
	{regex: `public-(sandbox|development|production)-` + uuidHex},       // Plaid Sandbox/Development/Production Public Token
	{regex: `link-(sandbox|development)-` + uuidHex},                    // Plaid Sandbox/Development Link Token
	{regex: `hbp_[0-9a-zA-Z]{36}`},                                      // Honeybadger API Key
	{regex: `woos-` + uuidHex},                                          // Woosmap Public Key
	{regex: `(https://)?[0-9a-zA-Z]{32}\@sentry\.io`},                   // Sentry Public DSN
	{regex: `sub-c-` + uuidHex},                                         // PubNub Subscribe Key
	{regex: `pub-c-` + uuidHex},                                         // PubNub Publish Key
	{regex: `hc[a-z]ik_([a-z0-9]{26,58})`},                              // Honeycomb Ingest Key
	{regex: `mob-` + uuidHex},                                           // LaunchDarkly Mobile Key
	{regex: `public-token-test-` + uuidHex},                             // Stytch Public Test Token
	{regex: `public-token-live-` + uuidHex},                             // Stytch Public Live Token
	{regex: `pdl_sdbx_apikey_[a-z\d]{26}_[a-zA-Z\d]{22}_[a-zA-Z\d]{3}`}, // Paddle Sandbox API Key
	// Regex + Keyword
	{`pk_test_[A-Za-z0-9]{24}(?:[A-Za-z0-9]{10})?(?:[A-Za-z0-9]{65})?`, []string{"stripe", "woo", "wcm"}}, // Stripe and WooCommerce Sandbox Publishable Key
	{`rk_test_[A-Za-z0-9]{24}(?:[A-Za-z0-9]{10})?(?:[A-Za-z0-9]{65})?`, []string{"stripe"}},               // Stripe Sandbox Restricted Key
	// {`sk_test_[A-Za-z0-9]{24}(?:[A-Za-z0-9]{10})?(?:[A-Za-z0-9]{65})?`, []string{"stripe", "woo", "wcm"}}, // Stripe and WooCommerce Sandbox Secret Key (not including b/c PII could be in test)
	{`pk_live_[A-Za-z0-9]{24}(?:[A-Za-z0-9]{10})?(?:[A-Za-z0-9]{65})?`, []string{"stripe", "woo", "wcm"}}, // Stripe and WooCommerce Publishable Live Key
	{`pk_test_[A-Za-z0-9_-]{40}`, []string{"paystack"}},                                                   // Paystack Test Public Key
	// {`sk_test_[A-Za-z0-9_-]{40}`, []string{"paystack"}}, // Paystack Test Secret Key (not including b/c PII could be in test)
	{`pk_live_[A-Za-z0-9_-]{40}`, []string{"paystack"}},                    // Paystack Live Public Key
	{`sandbox_[A-Za-z0-9]{8}_[A-Za-z0-9_-]{16}`, []string{"braintree"}},    // Braintree Sandbox Tokenization Key
	{`production_[A-Za-z0-9]{8}_[A-Za-z0-9_-]{16}`, []string{"braintree"}}, // Braintree Production Tokenization Key
	{`test_[0-9a-zA-Z]{32}`, []string{"adyen"}},                            // Adyen Test Client Key
	{`live_[0-9a-zA-Z]{32}`, []string{"adyen"}},                            // Adyen Live Client Key
	{`[A-Za-z0-9]{32}`, []string{"bugsnag"}},                               // Bugsnag SDK API Key
	{uuidHex, []string{"hcaptcha", "site_key", "sitekey"}},                 // hCaptcha Site Key
	{uuidHex, []string{"pendo"}},                                           // Pendo API Key
	{uuidHex, []string{"instrumentation"}},                                 // Azure Application Insights Instrumentation Key
	{`TEST-` + uuidHex, []string{"mercado"}},                               // Mercado Pago Test Public Key
	// {`TEST-[0-9]{8,16}-[0-9]{6}-[0-9a-f]{32}-[0-9]{7,10}`, []string{"mercado"}}, // Mercado Pago Test Access Token (not including b/c PII could be in test)
	{`[0-9a-fA-F]{32}`, []string{"mixpanel"}},                            // Mixpanel Project Token
	{`[0-9a-z]{6}\/[a-z_-]{2,100}`, []string{"logrocket"}},               // LogRocket Project ID
	{`[0-9a-f]{8}`, []string{"honeybadger"}},                             // Honeybadger Check In Token
	{`[a-zA-Z0-9=+]{21,24}`, []string{"raygun"}},                         // Raygun App API Key
	{`key_live_[0-9a-zA-Z]{32}`, []string{"branch"}},                     // Branch.io Production Branch Key
	{`key_test_[0-9a-zA-Z]{32}`, []string{"branch"}},                     // Branch.io Test Branch Key
	{`pub[0-9a-zA-Z]{32}`, []string{"datadog", "dd"}},                    // Datadog Client Token
	{`[0-9a-zA-Z]{6}`, []string{"klaviyo"}},                              // Klaviyo Company ID
	{`[0-9a-zA-Z]{32}`, []string{"storefront"}},                          // Shopify Storefront Public Access Token
	{`search-[0-9a-zA-Z_-]{24}`, []string{"swiftype"}},                   // Elastic Swiftype Public Search Key
	{`[0-9a-zA-Z_-]{20}`, []string{"swiftype"}},                          // Elastic Swiftype Public Engine Key
	{`pk.eyJ1Ijoi[0-9a-zA-Z_-]{1,}\.[0-9a-zA-Z-_]{1,}`, []string{"map"}}, // Mapbox Public Key
	{uuidHex, []string{"crisp"}},                                         // Crisp Website ID
	{`client-[a-zA-Z0-9]{43}`, []string{"statsdig"}},                     // Statsdig Client Key
	{`sdk-[a-zA-Z0-9]{15,16}`, []string{"growthbook"}},                   // Growthbook Client Key
	{`[a-zA-Z0-9\/=]{24}`, []string{"growthbook"}},                       // Growthbook Decryption Key
	{`[a-zA-Z0-9]{21,22}`, []string{"optimizely"}},                       // Optimizely SDK Key
	{`[0-9a-fA-F]{24}`, []string{"launchdarkly"}},                        //  LaunchDarkly Client Side ID
	{`pk_test_[0-9a-zA-Z]{20,70}`, []string{"clerk"}},                    // Clerk Test Publishable Key
	{`pk_live_[0-9a-zA-Z]{20,70}`, []string{"clerk"}},                    // Clerk Live Publishable Key
	// {`sk_test_[0-9a-zA-Z]{20,70}`, []string{"clerk"}}, // Clerk Test Secret Key (not including b/c PII could be in test)
	{`[0-9a-zA-Z]{40}`, []string{"smartlook"}},          // Smartlook Project Key
	{`[0-9A-Z]{5,6}`, []string{"fullstory"}},            // FullStory Org ID
	{uuidHex, []string{"zendesk", "zdassets.com"}},      // Zendesk Web Widget API Key
	{`[0-9a-zA-Z]{27}`, []string{"rudderstack"}},        // Rudderstack Write Key
	{uuidHex, []string{"web3forms"}},                    // Web3Forms Access Key
	{`[0-9]{12}`, []string{"2checkout", "twocheckout"}}, // 2Checkout Merchant Code
	{`test_[a-zA-Z0-9]{27}`, []string{"paddle"}},        // Paddle Client-Side Test Token
	{`live_[a-zA-Z0-9]{27}`, []string{"paddle"}},        // Paddle Client-Side Live Token
	{`pk_live_[0-9A-F]{16}`, []string{"magic"}},         // Magic Publishable Key
}

// Length bounds let the generated Expr reject impossible secret lengths before
// invoking the regex engine. Keys must exactly match the regex above.
var testAndPublicAPISecretLengthBounds = map[string][2]int{
	`[0-9a-f]{8}`:          {8, 8},
	`[0-9a-zA-Z]{6}`:       {6, 6},
	`[0-9A-Z]{5,6}`:        {5, 6},
	`[0-9]{12}`:            {12, 12},
	`[0-9a-zA-Z_-]{20}`:    {20, 20},
	`[0-9a-fA-F]{24}`:      {24, 24},
	`[a-zA-Z0-9\/=]{24}`:   {24, 24},
	`[a-zA-Z0-9]{21,22}`:   {21, 22},
	`[a-zA-Z0-9=+]{21,24}`: {21, 24},
	`[0-9a-zA-Z]{27}`:      {27, 27},
	`[0-9a-zA-Z]{40}`:      {40, 40},
}

// buildTestAndPublicAPIFilters renders one OR clause per testAndPublicAPIFilter.
// Entries without keywords match on the (anchored) secret regex alone; entries
// with keywords additionally require a keyword nearby on the line. containsAny
// lowercases its input, so the lowercase keywords match case-insensitively.
func buildTestAndPublicAPIFilters() string {
	var b strings.Builder
	var secretOnly []string
	for _, f := range testAndPublicAPIFilters {
		secretRegex := "`^" + f.regex + "$`"
		secretMatch := `matchesAny(finding["secret"], [` + secretRegex + `])`
		if bounds, ok := testAndPublicAPISecretLengthBounds[f.regex]; ok {
			secretLen := `len(finding["secret"])`
			if bounds[0] == bounds[1] {
				secretMatch = secretLen + " == " + strconv.Itoa(bounds[0]) + " && " + secretMatch
			} else {
				secretMatch = "(" + secretLen + " >= " + strconv.Itoa(bounds[0]) + " && " + secretLen + " <= " + strconv.Itoa(bounds[1]) + ") && " + secretMatch
			}
		}
		if len(f.keywords) == 0 {
			secretOnly = append(secretOnly, secretRegex)
			continue
		}
		b.WriteString("\n|| ")
		b.WriteString("(" + secretMatch + ` && filter.containsAnyNearMatch(finding, ` + exprStringListInline(f.keywords) + ", 150, 50, true))")
	}
	if len(secretOnly) > 0 {
		return "\n|| matchesAny(finding[\"secret\"], " + exprList(secretOnly) + ")" + b.String()
	}
	return b.String()
}

func exprList(parts []string) string {
	if len(parts) <= 1 {
		return "[" + strings.Join(parts, ", ") + "]"
	}
	var b strings.Builder
	b.WriteString("[\n")
	for i, p := range parts {
		b.WriteString("  " + p)
		if i < len(parts)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteByte(']')
	return b.String()
}

func exprStringListInline(ss []string) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = strconv.Quote(s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func exprStringList(ss []string) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = strconv.Quote(s)
	}
	return exprList(parts)
}
