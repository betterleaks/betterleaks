package scan

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
	"github.com/betterleaks/betterleaks/v2/sources"
)

const (
	routeSecret  = "k7Qm2pLx9Vw4nR8sT1yU6zA3bC5dE0fH"
	routeSecret2 = "m8Rn3qMy0Wx5oS9tU2zV7aB4cD6eF1gI"
)

func TestKeywordDoesNotPairDistantGeneric(t *testing.T) {
	scanner := mustNew(t, &config.Config{Rules: []config.Rule{
		routeProvider("adafruit-api-key", "adafruit", "Adafruit key"),
		routeGenericAPI(),
	}})
	raw := "embedding_model_handler('adafruit', 'embedding_model')\n" +
		"embedding_model = embedding_model_handler_obj(\n" +
		"    {'api_key': '" + routeSecret + "'}\n" +
		")\n"

	findings := scanner.ScanString(raw)
	require.Len(t, findings, 1)
	require.Equal(t, "generic-api-key", findings[0].RuleID)
	require.Equal(t, routeSecret, findings[0].Match.Value)
}

func TestKeywordRoutesWhenProviderRegexMatchesHit(t *testing.T) {
	generic := routeGenericAPI()
	generic.Regex = `(?i)(?:api_key|adafruit)[\s'"\x60]{0,3}[:=][\s'"\x60]{0,3}([a-zA-Z0-9_-]{16,})`
	scanner := mustNew(t, &config.Config{Rules: []config.Rule{
		routeProvider("adafruit-api-key", "adafruit", "Adafruit key"),
		generic,
	}})
	raw := "// api_key\nsee adafruit notes\nadafruit = \"" + routeSecret + "\"\n"
	var ruleIDs []string
	for _, finding := range scanner.ScanString(raw) {
		require.Equal(t, routeSecret, finding.Match.Value)
		ruleIDs = append(ruleIDs, finding.RuleID)
		if finding.RuleID == "adafruit-api-key" {
			require.Equal(t, "high", finding.Confidence)
		}
		if finding.RuleID == "generic-api-key" {
			require.Equal(t, "adafruit-api-key", finding.Attributes[sources.AttrScanPairedRules])
		}
	}
	require.ElementsMatch(t, []string{"generic-api-key", "adafruit-api-key"}, ruleIDs)
}

func TestKeywordWithoutRegexMatchStaysGeneric(t *testing.T) {
	scanner := mustNew(t, &config.Config{Rules: []config.Rule{
		routeProvider("adafruit-api-key", "adafruit", "Adafruit key"),
		routeGenericAPI(),
	}})
	findings := scanner.ScanString("see adafruit docs\napi_key = \"" + routeSecret + "\"\n")
	require.Len(t, findings, 1)
	require.Equal(t, "generic-api-key", findings[0].RuleID)
}

func TestKeywordInsideGenericMatchDoesNotRoute(t *testing.T) {
	scanner := mustNew(t, &config.Config{Rules: []config.Rule{
		routeProvider("adafruit-api-key", "adafruit", "Adafruit key"),
		routeGenericAPI(),
	}})
	secret := "adafruitk7Qm2pLx9Vw4nR8sT1yU6zAB"
	require.Len(t, secret, 32)
	findings := scanner.ScanString("api_key = \"" + secret + "\"\n")
	require.Len(t, findings, 1)
	require.Equal(t, "generic-api-key", findings[0].RuleID)
}

func TestGenericCredentialWordDoesNotRoute(t *testing.T) {
	provider := routeProvider("labeled-key", "key", "Labeled key")
	provider.Regex = rulebuilder.Assignment([]string{"key"}, `[a-z]{32}`)
	scanner := mustNew(t, &config.Config{Rules: []config.Rule{provider, routeGenericAPI()}})

	raw := "key = \"abcdefghijklmnopqrstuvwxyzabcdef\"\napi_key = \"" + routeSecret + "\"\n"
	var labeled, generic []string
	for _, finding := range scanner.ScanString(raw) {
		switch finding.RuleID {
		case "labeled-key":
			labeled = append(labeled, finding.Match.Value)
		case "generic-api-key":
			generic = append(generic, finding.Match.Value)
		default:
			t.Fatalf("unexpected rule %s", finding.RuleID)
		}
	}
	require.Equal(t, []string{"abcdefghijklmnopqrstuvwxyzabcdef"}, labeled)
	require.Equal(t, []string{routeSecret}, generic)
}

func TestProviderFilterRejectsRoutedGeneric(t *testing.T) {
	provider := routeProvider("adafruit-api-key", "adafruit", "Adafruit key")
	provider.FilterExpr = `true`
	generic := routeGenericAPI()
	generic.Regex = `(?i)(?:api_key|adafruit)[\s'"\x60]{0,3}[:=][\s'"\x60]{0,3}([a-zA-Z0-9_-]{16,})`
	scanner := mustNew(t, &config.Config{Rules: []config.Rule{provider, generic}})
	findings := scanner.ScanString("// api_key\nadafruit = \"" + routeSecret + "\"\n")
	require.Len(t, findings, 1)
	require.Equal(t, "generic-api-key", findings[0].RuleID)
}

func TestMultipleProvidersRouteOnlyRegexMatches(t *testing.T) {
	generic := routeGenericAPI()
	generic.Regex = `(?i)(?:api_key|adafruit|stripe)[\s'"\x60]{0,3}[:=][\s'"\x60]{0,3}([a-zA-Z0-9_-]{16,})`
	scanner := mustNew(t, &config.Config{Rules: []config.Rule{
		routeProvider("adafruit-api-key", "adafruit", "Adafruit key"),
		routeProvider("stripe-api-key", "stripe", "Stripe key"),
		generic,
	}})
	raw := "stripe billing\n// api_key\nadafruit hardware\nadafruit = \"" + routeSecret + "\"\n"
	var ids []string
	for _, finding := range scanner.ScanString(raw) {
		require.Equal(t, routeSecret, finding.Match.Value)
		ids = append(ids, finding.RuleID)
	}
	require.ElementsMatch(t, []string{"generic-api-key", "adafruit-api-key"}, ids)
}

func TestDirectAssignmentIsNotDuplicatedByRouting(t *testing.T) {
	generic := routeGenericAPI()
	generic.Regex = `(?i)(?:api_key|token)[\s'"]{0,3}[:=][\s'"]{0,3}([a-zA-Z0-9_-]{16,})`
	generic.Keywords = []string{"key", "token"}
	scanner := mustNew(t, &config.Config{Rules: []config.Rule{
		routeProvider("adafruit-api-key", "adafruit", "Adafruit key"),
		generic,
	}})
	var ids []string
	for _, finding := range scanner.ScanString("adafruit_token = \"" + routeSecret + "\"\n") {
		require.Equal(t, routeSecret, finding.Match.Value)
		ids = append(ids, finding.RuleID)
	}
	require.ElementsMatch(t, []string{"generic-api-key", "adafruit-api-key"}, ids)
}

func TestTokenRuleDoesNotClaimGeneric(t *testing.T) {
	scanner := mustNew(t, &config.Config{Rules: []config.Rule{
		{
			ID:          "openai-api-key",
			Description: "OpenAI key",
			Confidence:  "high",
			Regex:       `sk-[a-z]{8}`,
			Keywords:    []string{"sk-"},
		},
		routeGenericAPI(),
	}})
	var ids []string
	for _, finding := range scanner.ScanString("sk-abcdefgh\napi_key = \"" + routeSecret + "\"\n") {
		ids = append(ids, finding.RuleID+":"+finding.Match.Value)
	}
	require.ElementsMatch(t, []string{
		"openai-api-key:sk-abcdefgh",
		"generic-api-key:" + routeSecret,
	}, ids)
}

func TestRequiredComponentBlocksRoutedGeneric(t *testing.T) {
	provider := routeProvider("adafruit-api-key", "adafruit", "Adafruit key")
	provider.Components = []config.Component{{RuleID: "account-id", Within: "2L"}}
	account := config.Rule{
		ID:         "account-id",
		Regex:      `acct-([a-z]+)`,
		Keywords:   []string{"acct-"},
		SkipReport: true,
	}
	generic := routeGenericAPI()
	generic.Regex = `(?i)(?:api_key|adafruit)[\s'"\x60]{0,3}[:=][\s'"\x60]{0,3}([a-zA-Z0-9_-]{16,})`
	cfg := &config.Config{Rules: []config.Rule{provider, account, generic}}

	missing := mustNew(t, cfg).ScanString("// api_key\nadafruit = \"" + routeSecret + "\"\n")
	require.Len(t, missing, 1)
	require.Equal(t, "generic-api-key", missing[0].RuleID)

	found := mustNew(t, cfg).ScanString("// api_key\nadafruit = \"" + routeSecret + "\"\nacct-prod\n")
	var ids []string
	for _, finding := range found {
		require.Equal(t, routeSecret, finding.Match.Value)
		ids = append(ids, finding.RuleID)
		if finding.RuleID == "adafruit-api-key" {
			require.Len(t, finding.ComponentSets, 1)
		}
	}
	require.ElementsMatch(t, []string{"generic-api-key", "adafruit-api-key"}, ids)
}

func TestDecodedKeywordRoutesWhenRegexMatches(t *testing.T) {
	generic := routeGenericAPI()
	generic.Regex = `(?i)(?:api_key|adafruit)[\s'"\x60]{0,3}[:=][\s'"\x60]{0,3}([a-zA-Z0-9_-]{16,})`
	scanner := mustNew(t, &config.Config{Rules: []config.Rule{
		routeProvider("adafruit-api-key", "adafruit", "Adafruit key"),
		generic,
	}}, WithMaxDecodeDepth(1))
	raw := "// api_key\nadafruit = \"" + routeSecret + "\"\n"
	findings := scanner.ScanString(base64.StdEncoding.EncodeToString([]byte(raw)))
	var ids []string
	for _, finding := range findings {
		require.Equal(t, routeSecret, finding.Match.Value)
		ids = append(ids, finding.RuleID)
	}
	require.ElementsMatch(t, []string{"generic-api-key", "adafruit-api-key"}, ids)
}

func TestPathRestrictsRoutedGeneric(t *testing.T) {
	provider := routeProvider("hashicorp-tf-password", "password", "Terraform password")
	provider.Regex = rulebuilder.Assignment([]string{"password"}, `[a-zA-Z0-9_-]{16,}`)
	provider.Path = `(?i)\.tf$`
	scanner := mustNew(t, &config.Config{Rules: []config.Rule{provider, routeGenericPassword()}})
	raw := "password = \"" + routeSecret + "\" # development password\n"

	unscoped := scanner.ScanString(raw)
	require.Len(t, unscoped, 1)
	require.Equal(t, "generic-password", unscoped[0].RuleID)

	routed := scanner.detectFragment(t.Context(), sources.Fragment{
		Raw:        raw,
		Attributes: map[string]string{"path": "main.tf"},
	})
	var ids []string
	for _, finding := range routed {
		require.Equal(t, routeSecret, finding.Match.Value)
		ids = append(ids, finding.RuleID)
	}
	require.ElementsMatch(t, []string{"generic-password", "hashicorp-tf-password"}, ids)
}

func TestMinimumConfidenceKeepsRoutedProvider(t *testing.T) {
	generic := routeGenericAPI()
	generic.Regex = `(?i)(?:api_key|adafruit)[\s'"\x60]{0,3}[:=][\s'"\x60]{0,3}([a-zA-Z0-9_-]{16,})`
	scanner := mustNew(t, &config.Config{Rules: []config.Rule{
		routeProvider("adafruit-api-key", "adafruit", "Adafruit key"),
		generic,
	}}, WithMinimumConfidence(ConfidenceHigh))
	findings := scanner.ScanString("// api_key\nadafruit = \"" + routeSecret + "\"\n")
	require.Len(t, findings, 1)
	require.Equal(t, "adafruit-api-key", findings[0].RuleID)

	withoutKeyword := scanner.ScanString("api_key = \"" + routeSecret + "\"\n")
	require.Empty(t, withoutKeyword)
}

func routeProvider(id, keyword, description string) config.Rule {
	return config.Rule{
		ID:          id,
		Description: description,
		Confidence:  "high",
		Regex:       rulebuilder.Assignment([]string{keyword}, `[a-zA-Z0-9_-]{32}`),
		Keywords:    []string{keyword},
		Tags:        []string{"provider:" + keyword},
	}
}

func routeGenericPassword() config.Rule {
	return config.Rule{
		ID:          "generic-password",
		Description: "generic password",
		Confidence:  "low",
		Specificity: -80,
		Regex:       `(?i)password[\s'"]{0,3}[:=][\s'"]{0,3}([a-zA-Z0-9_-]{16,})`,
		Keywords:    []string{"passw"},
	}
}

func routeGenericAPI() config.Rule {
	return config.Rule{
		ID:          "generic-api-key",
		Description: "generic",
		Confidence:  "low",
		Specificity: -100,
		Regex:       `(?i)api_key[\s'"\x60]{0,3}[:=][\s'"\x60]{0,3}([a-zA-Z0-9_-]{16,})`,
		Keywords:    []string{"key"},
	}
}
