package main

import (
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"text/template"

	"github.com/betterleaks/betterleaks/cmd/generate/config/base"
	"github.com/betterleaks/betterleaks/cmd/generate/config/rules"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/logging"
)

const (
	templatePath = "rules/config.tmpl"
)

//go:generate go run $GOFILE ../../../config/betterleaks.toml

// tomlQuote returns a TOML-safe quoted string. Values containing liquid
// template syntax ({{ ... }}) use TOML literal strings (single quotes) to
// avoid escaping inner double quotes used by filters like append/b64enc.
func tomlQuote(s string) string {
	if strings.Contains(s, "{{") {
		return "'" + s + "'"
	}
	return fmt.Sprintf("%q", s)
}

func tomlValue(v any) string {
	switch val := v.(type) {
	case string:
		return fmt.Sprintf("%q", val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	case int:
		return fmt.Sprintf("%d", val)
	case int64:
		return fmt.Sprintf("%d", val)
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%g", val)
	case []any:
		parts := make([]string, 0, len(val))
		for _, item := range val {
			parts = append(parts, tomlValue(item))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		return fmt.Sprintf("%q", fmt.Sprintf("%v", v))
	}
}

func main() {
	if len(os.Args) < 2 {
		_, _ = os.Stderr.WriteString("Specify path to the betterleaks.toml config\n")
		os.Exit(2)
	}
	betterleaksConfigPath := os.Args[1]

	configRules := []*config.Rule{
		rules.OnePasswordSecretKey(),
		rules.OnePasswordServiceAccountToken(),
		rules.AssemblyAI(),
		rules.AdafruitAPIKey(),
		rules.AdobeClientID(),
		rules.AdobeClientSecret(),
		rules.AgeSecretKey(),
		rules.AirtableApiKey(),
		rules.AirtablePersonalAccessToken(),
		rules.AlgoliaApiKey(),
		rules.AlibabaAccessKey(),
		rules.AlibabaSecretKey(),
		rules.AmazonBedrockAPIKeyLongLived(),
		rules.AmazonBedrockAPIKeyShortLived(),
		rules.AnthropicAdminApiKey(),
		rules.AnthropicApiKey(),
		rules.ArtifactoryApiKey(),
		rules.ArtifactoryReferenceToken(),
		rules.AsanaClientID(),
		rules.AsanaClientSecret(),
		rules.Atlassian(),
		rules.Authress(),
		rules.AWS(),
		rules.AzureActiveDirectoryClientSecret(),
		rules.BitBucketClientID(),
		rules.BitBucketClientSecret(),
		rules.BittrexAccessKey(),
		rules.BittrexSecretKey(),
		rules.Beamer(),
		rules.Cerebras(),
		rules.CodecovAccessToken(),
		rules.CoinbaseAccessToken(),
		rules.ClickHouseCloud(),
		rules.Clojars(),
		rules.CloudflareAPIKey(),
		rules.CloudflareGlobalAPIKey(),
		rules.CloudflareOriginCAKey(),
		rules.CohereAPIToken(),
		rules.ConfluentAccessToken(),
		rules.ConfluentSecretKey(),
		rules.Contentful(),
		rules.CursorAPIKey(),
		rules.CurlHeaderAuth(),
		rules.CurlBasicAuth(),
		rules.Databricks(),
		rules.Deepgram(),
		rules.DeepSeek(),
		rules.DatadogtokenAccessToken(),
		rules.DefinedNetworkingAPIToken(),
		rules.DigitalOceanPAT(),
		rules.DigitalOceanOAuthToken(),
		rules.DigitalOceanRefreshToken(),
		rules.DiscordAPIToken(),
		rules.DiscordClientID(),
		rules.DiscordClientSecret(),
		rules.Doppler(),
		rules.DropBoxAPISecret(),
		rules.DropBoxLongLivedAPIToken(),
		rules.DropBoxShortLivedAPIToken(),
		rules.DroneciAccessToken(),
		rules.Duffel(),
		rules.Dynatrace(),
		rules.EasyPost(),
		rules.ElevenLabs(),
		rules.EndorLabsAPIKey(),
		rules.EndorLabsAPISecret(),
		rules.EasyPostTestAPI(),
		rules.EtsyAccessToken(),
		rules.FacebookSecret(),
		rules.FacebookAccessToken(),
		rules.FacebookPageAccessToken(),
		rules.FastlyAPIToken(),
		rules.FinicityClientSecret(),
		rules.FinicityAPIToken(),
		rules.FlickrAccessToken(),
		rules.FinnhubAccessToken(),
		rules.FlutterwavePublicKey(),
		rules.FlutterwaveSecretKey(),
		rules.FlutterwaveEncKey(),
		rules.FlyIOAccessToken(),
		rules.FrameIO(),
		rules.Freemius(),
		rules.FreshbooksAccessToken(),
		rules.GoCardless(),
		// TODO figure out what makes sense for GCP
		// rules.GCPServiceAccount(),
		rules.GCPAPIKey(),
		rules.GiteaAccessToken(),
		rules.GitHubPat(),
		rules.GitHubFineGrainedPat(),
		rules.GitHubOauth(),
		rules.GitHubApp(),
		rules.GitHubRefresh(),
		rules.GitlabCiCdJobToken(),
		rules.GitlabDeployToken(),
		rules.GitlabFeatureFlagClientToken(),
		rules.GitlabFeedToken(),
		rules.GitlabIncomingMailToken(),
		rules.GitlabKubernetesAgentToken(),
		rules.GitlabOauthAppSecret(),
		rules.GitlabPat(),
		rules.GitlabPatRoutable(),
		rules.GitlabPipelineTriggerToken(),
		rules.GitlabRunnerRegistrationToken(),
		rules.GitlabRunnerAuthenticationToken(),
		rules.GitlabRunnerAuthenticationTokenRoutable(),
		rules.GitlabScimToken(),
		rules.GitlabSessionCookie(),
		rules.GitterAccessToken(),
		rules.Groq(),
		rules.Greptile(),
		rules.GrafanaApiKey(),
		rules.GrafanaCloudApiToken(),
		rules.GrafanaServiceAccountToken(),
		rules.HarnessApiKey(),
		rules.HashiCorpTerraform(),
		rules.HashicorpField(),
		rules.Heroku(),
		rules.HerokuV2(),
		rules.HubSpot(),
		rules.HuggingFaceAccessToken(),
		rules.HuggingFaceOrganizationApiToken(),
		rules.Intercom(),
		rules.Intra42ClientSecret(),
		rules.JFrogAPIKey(),
		rules.JFrogIdentityToken(),
		rules.JWT(),
		rules.JWTBase64(),
		rules.KrakenAccessToken(),
		rules.KubernetesSecret(),
		rules.KucoinAccessToken(),
		rules.KucoinSecretKey(),
		rules.LaunchDarklyAccessToken(),
		rules.LinearAPIToken(),
		rules.LinearClientSecret(),
		rules.LinkedinClientID(),
		rules.LinkedinClientSecret(),
		rules.LobAPIToken(),
		rules.LobPubAPIToken(),
		rules.LookerClientID(),
		rules.LookerClientSecret(),
		rules.MailChimp(),
		rules.MailGunPubAPIToken(),
		rules.MailGunPrivateAPIToken(),
		rules.MailGunSigningKey(),
		rules.MapBox(),
		rules.Mistral(),
		rules.MattermostAccessToken(),
		rules.MaxMindLicenseKey(),
		rules.Meraki(),
		rules.MessageBirdAPIToken(),
		rules.MessageBirdClientID(),
		rules.NetlifyAccessToken(),
		rules.NewRelicUserID(),
		rules.NewRelicUserKey(),
		rules.NewRelicBrowserAPIKey(),
		rules.NewRelicInsertKey(),
		rules.Notion(),
		rules.NPM(),
		rules.NugetConfigPassword(),
		rules.NvidiaAPIKey(),
		rules.NytimesAccessToken(),
		rules.Ollama(),
		rules.OctopusDeployApiKey(),
		rules.OktaAccessToken(),
		rules.OpenAI(),
		rules.OpenRouter(),
		rules.OpenshiftUserToken(),
		rules.PostHogProjectAPIKey(),
		rules.PostHogPersonalAPIKey(),
		rules.PlaidAccessID(),
		rules.PlaidSecretKey(),
		rules.PlaidAccessToken(),
		rules.PlanetScalePassword(),
		rules.PlanetScaleAPIToken(),
		rules.PlanetScaleOAuthToken(),
		rules.PostManAPI(),
		rules.Prefect(),
		rules.PrivateAIToken(),
		rules.PrivateKey(),
		rules.PrivateKeyPKCS12File(),
		rules.PulumiAPIToken(),
		rules.PyPiUploadToken(),
		rules.RapidAPIAccessToken(),
		rules.Replicate(),
		rules.ReadMe(),
		rules.RubyGemsAPIToken(),
		rules.ScalingoAPIToken(),
		rules.SendbirdAccessID(),
		rules.SendbirdAccessToken(),
		rules.SendGridAPIToken(),
		rules.SendInBlueAPIToken(),
		rules.SentryAccessToken(),
		rules.SentryOrgToken(),
		rules.SentryUserToken(),
		rules.SettlemintApplicationAccessToken(),
		rules.SettlemintPersonalAccessToken(),
		rules.SettlemintServiceAccessToken(),
		rules.ShippoAPIToken(),
		rules.ShopifyAccessToken(),
		rules.ShopifyCustomAccessToken(),
		rules.ShopifyPrivateAppAccessToken(),
		rules.ShopifySharedSecret(),
		rules.SidekiqSecret(),
		rules.SidekiqSensitiveUrl(),
		rules.SlackBotToken(),
		rules.SlackUserToken(),
		rules.SlackAppLevelToken(),
		rules.SlackConfigurationToken(),
		rules.SlackConfigurationRefreshToken(),
		rules.SlackLegacyBotToken(),
		rules.SlackLegacyWorkspaceToken(),
		rules.SlackLegacyToken(),
		rules.SlackWebHookUrl(),
		rules.Snyk(),
		rules.Sonar(),
		rules.SourceGraph(),
		rules.StabilityAI(),
		rules.StripeAccessToken(),
		rules.SquareAccessToken(),
		rules.SquareSpaceAccessToken(),
		rules.SumoLogicAccessID(),
		rules.SumoLogicAccessToken(),
		rules.TeamsWebhook(),
		rules.TogetherAI(),
		rules.TelegramBotToken(),
		rules.TravisCIAccessToken(),
		rules.Twilio(),
		rules.TwitchAPIToken(),
		rules.TwitterAPIKey(),
		rules.TwitterAPISecret(),
		rules.TwitterAccessToken(),
		rules.TwitterAccessSecret(),
		rules.TwitterBearerToken(),
		rules.Typeform(),
		rules.VercelAPIToken(),
		rules.VercelPersonalAccessToken(),
		rules.VercelIntegrationToken(),
		rules.VercelAppAccessToken(),
		rules.VercelAppRefreshToken(),
		rules.VercelAIGatewayKey(),
		rules.VaultBatchToken(),
		rules.VaultServiceToken(),
		rules.WeightsAndBiases(),
		rules.WeightsAndBiasesV1(),
		rules.XAI(),
		rules.YandexAPIKey(),
		rules.YandexAWSAccessToken(),
		rules.YandexAccessToken(),
		rules.ZendeskSecretKey(),
		rules.GenericCredential(),
		rules.InfracostAPIToken(),
	}

	// ensure rules have unique ids
	ruleLookUp := make(map[string]config.Rule, len(configRules))
	for _, rule := range configRules {
		if err := rule.Check(); err != nil {
			logging.Fatal().Err(err).
				Str("rule-id", rule.RuleID).
				Msg("Failed to validate rule")
		}

		// check if rule is in ruleLookUp
		if _, ok := ruleLookUp[rule.RuleID]; ok {
			logging.Fatal().
				Str("rule-id", rule.RuleID).
				Msg("rule id is not unique")
		}
		// TODO: eventually change all the signatures to get ride of this
		// nasty dereferencing.
		ruleLookUp[rule.RuleID] = *rule

		// Slices are de-duplicated with a map, every iteration has a different order.
		// This is an awkward workaround.
		for _, allowlist := range rule.Allowlists {
			slices.Sort(allowlist.Commits)
			slices.Sort(allowlist.StopWords)
		}
	}

	funcMap := template.FuncMap{
		"tomlQuote": tomlQuote,
		"tomlInlineTable": func(m map[string]string) string {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			parts := make([]string, 0, len(keys))
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%s = %s", k, tomlQuote(m[k])))
			}
			return "{ " + strings.Join(parts, ", ") + " }"
		},
		"tomlInlineTableAny": func(m map[string]any) string {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			parts := make([]string, 0, len(keys))
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%s = %s", k, tomlValue(m[k])))
			}
			return "{ " + strings.Join(parts, ", ") + " }"
		},
	}
	tmpl, err := template.New("config.tmpl").Funcs(funcMap).ParseFiles(templatePath)
	if err != nil {
		logging.Fatal().Err(err).Msg("Failed to parse template")
	}

	f, err := os.Create(betterleaksConfigPath)
	if err != nil {
		logging.Fatal().Err(err).Msg("Failed to create rules.toml")
	}
	defer f.Close()

	cfg := base.CreateGlobalConfig()
	cfg.Rules = ruleLookUp
	for _, allowlist := range cfg.Allowlists {
		slices.Sort(allowlist.Commits)
		slices.Sort(allowlist.StopWords)
	}
	if err = tmpl.Execute(f, cfg); err != nil {
		logging.Fatal().Err(err).Msg("could not execute template")
	}
}
