package rules

import (
	"strconv"
	"strings"
)

const genericAPIKeyMatchFilter = `(?i)(?:access(?:ibility|or)|access[_.-]?id|random[_.-]?access|api[_.-]?(?:id|name|version)|rapid|capital|[a-z0-9-]*?api[a-z0-9-]*?:jar:|author|X-MS-Exchange-Organization-Auth|Authentication-Results|(?:credentials?[_.-]?id|withCredentials)|(?:bucket|foreign|hot|idx|natural|primary|pub(?:lic)?|schema|sequence)[_.-]?key|(?:turkey)|key[_.-]?(?:alias|board|code|frame|id|length|mesh|name|pair|press(?:ed)?|ring|selector|signature|size|stone|storetype|word|up|down|left|right)|key[_.-]?vault[_.-]?(?:id|name)|keyVaultToStoreSecrets|key(?:store|tab)[_.-]?(?:file|path)|issuerkeyhash|(?-i:[DdMm]onkey|[DM]ONKEY)|keying|(?:secret)[_.-]?(?:length|name|size)|UserSecretsId|(?:csrf)[_.-]?token|(?:io\.jsonwebtoken[ \t]?:[ \t]?[\w-]+)|(?:api|credentials|token)[_.-]?(?:endpoint|ur[il])|public[_.-]?token|(?:key|token)[_.-]?file|(?-i:(?:[A-Z_]+=\n[A-Z_]+=|[a-z_]+=\n[a-z_]+=)(?:\n|\z))|(?-i:(?:[A-Z.]+=\n[A-Z.]+=|[a-z.]+=\n[a-z.]+=)(?:\n|\z)))`

var genericAPIKeyFilter = buildGenericAPIKeyFilter()

func buildGenericAPIKeyFilter() string {
	return `matchesAny(finding["secret"], [` + "`^[a-zA-Z_.-]+$`" + `])
|| (matchesAny(finding["match"], [` + "`" + genericAPIKeyMatchFilter + "`" + `]) || containsAny(finding["secret"], ` + exprStringList(DefaultStopWords) + `))
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
	{regex: `sb_publishable_[A-Za-z0-9_-]{31}`},
	{regex: `0x4AAAAAA[A-Za-z0-9_-]{15}`},
	{regex: `FCM[a-zA-Z0-9]{13}`},
	{regex: `ysc1_[A-Za-z0-9_-]{48}`},
	{regex: `phc_[A-Za-z0-9_-]{43,44}`},
	{regex: `APP_USR-` + uuidHex},
	{regex: `access-(sandbox|development)-` + uuidHex},
	{regex: `asset-report-(sandbox|development)-` + uuidHex},
	{regex: `public-(sandbox|development|production)-` + uuidHex},
	{regex: `link-(sandbox|development)-` + uuidHex},
	{regex: `hbp_[0-9a-zA-Z]{36}`},
	{regex: `woos-` + uuidHex},
	{regex: `(https://)?[0-9a-zA-Z]{32}\@sentry\.io`},
	{regex: `sub-c-` + uuidHex},
	{regex: `pub-c-` + uuidHex},
	{regex: `hc[a-z]ik_([a-z0-9]{26,58})`},
	{regex: `mob-` + uuidHex},
	{regex: `public-token-test-` + uuidHex},
	{regex: `public-token-live-` + uuidHex},
	{regex: `pdl_sdbx_apikey_[a-z\d]{26}_[a-zA-Z\d]{22}_[a-zA-Z\d]{3}`},
	// Regex + Keyword
	{`pk_test_[A-Za-z0-9]{24}(?:[A-Za-z0-9]{10})?(?:[A-Za-z0-9]{65})?`, []string{"stripe", "woo", "wcm"}},
	{`rk_test_[A-Za-z0-9]{24}(?:[A-Za-z0-9]{10})?(?:[A-Za-z0-9]{65})?`, []string{"stripe"}},
	{`sk_test_[A-Za-z0-9]{24}(?:[A-Za-z0-9]{10})?(?:[A-Za-z0-9]{65})?`, []string{"stripe", "woo", "wcm"}},
	{`pk_live_[A-Za-z0-9]{24}(?:[A-Za-z0-9]{10})?(?:[A-Za-z0-9]{65})?`, []string{"stripe", "woo", "wcm"}},
	{`pk_test_[A-Za-z0-9_-]{40}`, []string{"paystack"}},
	{`sk_test_[A-Za-z0-9_-]{40}`, []string{"paystack"}},
	{`pk_live_[A-Za-z0-9_-]{40}`, []string{"paystack"}},
	{`sandbox_[A-Za-z0-9]{8}_[A-Za-z0-9_-]{16}`, []string{"braintree"}},
	{`production_[A-Za-z0-9]{8}_[A-Za-z0-9_-]{16}`, []string{"braintree"}},
	{`test_[0-9a-zA-Z]{32}`, []string{"adyen"}},
	{`live_[0-9a-zA-Z]{32}`, []string{"adyen"}},
	{`[A-Za-z0-9]{32}`, []string{"bugsnag"}},
	{uuidHex, []string{"hcaptcha", "site_key", "sitekey"}},
	{uuidHex, []string{"pendo"}},
	{uuidHex, []string{"instrumentation"}},
	{`TEST-` + uuidHex, []string{"mercado"}},
	{`TEST-[0-9]{8,16}-[0-9]{6}-[0-9a-f]{32}-[0-9]{7,10}`, []string{"mercado"}},
	{`[0-9a-fA-F]{32}`, []string{"mixpanel"}},
	{`[0-9a-z]{6}\/[a-z_-]{2,100}`, []string{"logrocket"}},
	{`[0-9a-f]{8}`, []string{"honeybadger"}},
	{`[a-zA-Z0-9=+]{21,24}`, []string{"raygun"}},
	{`key_live_[0-9a-zA-Z]{32}`, []string{"branch"}},
	{`key_test_[0-9a-zA-Z]{32}`, []string{"branch"}},
	{`pub[0-9a-zA-Z]{32}`, []string{"datadog", "dd"}},
	{`[0-9a-zA-Z]{6}`, []string{"klaviyo"}},
	{`[0-9a-zA-Z]{32}`, []string{"storefront"}},
	{`search-[0-9a-zA-Z_-]{24}`, []string{"swiftype"}},
	{`[0-9a-zA-Z_-]{20}`, []string{"swiftype"}},
	{`pk.eyJ1Ijoi[0-9a-zA-Z_-]{1,}\.[0-9a-zA-Z-_]{1,}`, []string{"map"}},
	{uuidHex, []string{"crisp"}},
	{`client-[a-zA-Z0-9]{43}`, []string{"statsdig"}},
	{`sdk-[a-zA-Z0-9]{15,16}`, []string{"growthbook"}},
	{`[a-zA-Z0-9\/=]{24}`, []string{"growthbook"}},
	{`[a-zA-Z0-9]{21,22}`, []string{"optimizely"}},
	{`[0-9a-fA-F]{24}`, []string{"launchdarkly"}},
	{`pk_test_[0-9a-zA-Z]{20,70}`, []string{"clerk"}},
	{`pk_live_[0-9a-zA-Z]{20,70}`, []string{"clerk"}},
	{`sk_test_[0-9a-zA-Z]{20,70}`, []string{"clerk"}},
	{`[0-9a-zA-Z]{40}`, []string{"smartlook"}},
	{`[0-9A-Z]{5,6}`, []string{"fullstory"}},
	{uuidHex, []string{"zendesk", "zdassets.com"}},
	{`[0-9a-zA-Z]{27}`, []string{"rudderstack"}},
	{uuidHex, []string{"web3forms"}},
	{`[0-9]{12}`, []string{"2checkout", "twocheckout"}},
	{`test_[a-zA-Z0-9]{27}`, []string{"paddle"}},
	{`live_[a-zA-Z0-9]{27}`, []string{"paddle"}},
	{`pk_live_[0-9A-F]{16}`, []string{"magic"}},
}

// buildTestAndPublicAPIFilters renders one OR clause per testAndPublicAPIFilter.
// Entries without keywords match on the (anchored) secret regex alone; entries
// with keywords additionally require a keyword nearby on the line. containsAny
// lowercases its input, so the lowercase keywords match case-insensitively.
func buildTestAndPublicAPIFilters() string {
	var b strings.Builder
	for _, f := range testAndPublicAPIFilters {
		secretMatch := `matchesAny(finding["secret"], [r"""^` + f.regex + `$"""])`
		b.WriteString("\n|| ")
		if len(f.keywords) == 0 {
			b.WriteString(secretMatch)
			continue
		}
		b.WriteString("(" + secretMatch + ` && containsAny(finding["line"], ` + exprStringListInline(f.keywords) + "))")
	}
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
