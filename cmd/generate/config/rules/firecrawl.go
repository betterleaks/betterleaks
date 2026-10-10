package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/v2/config"
)

// https://docs.firecrawl.dev/api-reference/endpoint/credit-usage
// Keys are "fc-" followed by a dashless UUID; the API itself checks ^fc-[0-9a-f]{32}$.
// The endpoint is read-only and does not consume credits.
const firecrawlValidateExpr = `let r = http.get("https://api.firecrawl.dev/v2/team/credit-usage", {
  "Authorization": "Bearer " + finding["secret"],
  "Accept": "application/json"
});
r.status == 200 && r.json?.success == true ? {
  "result": "valid"
} : r.status == 401 ? {
  "result": "invalid", "reason": "Unauthorized"
} : validate.unknown(r)`

func FirecrawlAPIKey() *config.Rule {
	r := config.Rule{
		ID:          "firecrawl-api-key",
		Confidence:  "high",
		Description: "Detected a Firecrawl API Key, which may expose web scraping and crawling services and account credits to unauthorized use.",
		// Word boundaries instead of the unique-token suffix so keys followed by
		// & or , (URL query strings, function args) are still caught.
		Regex:        `\b(fc-[a-f0-9]{32})\b`,
		Keywords:     []string{"fc-"},
		ValidateExpr: firecrawlValidateExpr,
		// 32 hex chars is short: <= 3.5 would drop ~4% of real keys, <= 3.0 drops none
		// while still rejecting repeated placeholders such as fc-000... or fc-deadbeef...
		FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	}

	hex := secrets.NewSecretWithEntropy(utils.Hex("32"), 3.5)
	key := "fc-" + hex
	tps := utils.GenerateSampleSecrets("firecrawl", key)
	tps = append(tps,
		`app = FirecrawlApp(api_key="`+key+`")`,
		`https://api.firecrawl.dev/v2/scrape?api_key=`+key+`&url=example.com`,
		`scrape(`+key+`, timeout=30)`,
	)
	fps := []string{
		// Too short
		`FIRECRAWL_API_KEY=` + key[:len(key)-1],
		// Too long
		`FIRECRAWL_API_KEY=` + key + hex[:8],
		// Uppercase; Firecrawl only issues lowercase keys
		`FIRECRAWL_API_KEY=FC-` + hex,
		// Documentation placeholder
		`FIRECRAWL_API_KEY=fc-YOUR_API_KEY`,
		// Low entropy
		`FIRECRAWL_API_KEY=fc-00000000000000000000000000000000`,
		`FIRECRAWL_API_KEY=fc-deadbeefdeadbeefdeadbeefdeadbeef`,
	}
	return utils.Validate(r, tps, fps)
}
