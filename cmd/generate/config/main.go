package main

import (
	"fmt"
	"os"
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

// tomlKeyQuote quotes a TOML key if it contains characters that require quoting
// (e.g. dots, spaces). Bare keys only allow [A-Za-z0-9_-].
func tomlKeyQuote(key string) string {
	if strings.ContainsAny(key, ". \t") {
		return fmt.Sprintf("%q", key)
	}
	return key
}

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
		rules.AivenAuthToken(),
		rules.AssemblyAI(),
		rules.AdafruitAPIKey(),
		rules.AdobeClientID(),
		rules.AdobeClientSecret(),
		rules.AbuseIPDBAPIKey(),
		rules.AgeSecretKey(),
		rules.AikidoClientID(),
		rules.AikidoClientSecret(),
		rules.AikidoCIToken(),
		rules.AirtableApiKey(),
		rules.AirtablePersonalAccessToken(),
		rules.AirtableOAuthToken(),
		rules.AlgoliaApplicationID(),
		rules.AlgoliaApiKey(),
		rules.AlibabaAccessKey(),
		rules.AlibabaSecretKey(),
		rules.AlibabaSTSAccessKeyID(),
		rules.AlibabaSTSSecurityToken(),
		rules.AlibabaSTSAccessKeySecret(),
		rules.AmazonBedrockAPIKeyLongLived(),
		rules.AmazonBedrockAPIKeyShortLived(),
		rules.AmplitudeSecretKey(),
		rules.AnthropicAdminApiKey(),
		rules.AnthropicApiKey(),
		rules.ApifyAPIToken(),
		rules.ApolloAPIKey(),
		rules.ArtifactoryJFrogURL(),
		rules.ArtifactoryApiKey(),
		rules.ArtifactoryReferenceToken(),
		rules.AsanaClientID(),
		rules.AsanaClientSecret(),
		rules.AsaasAPIToken(),
		rules.Atlassian(),
		rules.Auth0Domain(),
		rules.Auth0ClientID(),
		rules.Auth0ClientSecret(),
		rules.Authress(),
		rules.AWS(),
		rules.AWSSecretAccessKey(),
		rules.AzureTenantID(),
		rules.AzureClientID(),
		rules.AzureActiveDirectoryClientSecret(),
		rules.AzureStorageAccountName(),
		rules.AzureStorageAccountKey(),
		rules.AzureAppConfigurationConnectionString(),
		rules.AzureServiceBusConnectionString(),
		rules.BitBucketClientID(),
		rules.BitBucketClientSecret(),
		rules.BitriseAccessToken(),
		rules.BitlyAccessToken(),
		rules.BittrexAccessKey(),
		rules.BittrexSecretKey(),
		rules.Beamer(),
		rules.BoxAPIAccessToken(),
		rules.BrowserStackUsername(),
		rules.BrowserStackAccessKey(),
		rules.BraveSearchAPIKey(),
		rules.BuildkiteUserAccessToken(),
		rules.BuildkiteServiceToken(),
		rules.CanvaClientID(),
		rules.CanvaClientSecret(),
		rules.CartesiaAPIKey(),
		rules.Cerebras(),
		rules.Civo(),
		rules.ClickHouseCloudKeyID(),
		rules.ClickHouseCloud(),
		rules.ClickUpPersonalAPIToken(),
		rules.Clojars(),
		rules.CloudflareAPIKey(),
		rules.CloudflareGlobalAPIKey(),
		rules.CloudflareOriginCAKey(),
		rules.CloudsmithAPIKey(),
		rules.CloudinaryCloudName(),
		rules.CloudinaryAPIKey(),
		rules.CloudinaryAPISecret(),
		rules.CockroachLabsCloudAPIKey(),
		rules.CodecovAccessToken(),
		rules.ClerkSecretKey(),
		rules.CoinbaseAccessToken(),
		rules.CohereAPIToken(),
		rules.ConfluentAccessToken(),
		rules.ConfluentSecretKey(),
		rules.ConfigCatSDKKey(),
		rules.ConfigCatSDKKeyExtended(),
		rules.Contentful(),
		rules.CoverallsPersonalAPIToken(),
		rules.CouchbaseCapellaAPIKey(),
		rules.CursorAPIKey(),
		rules.CurlHeaderAuth(),
		rules.CurlBasicAuth(),
		rules.Databricks(),
		rules.DataStaxAstraApplicationToken(),
		rules.Deepgram(),
		rules.DeepSeek(),
		rules.DatadogAPIKey(),
		rules.DatadogApplicationKey(),
		rules.DataGovAPIKey(),
		rules.DefinedNetworkingAPIToken(),
		rules.DenoAccountToken(),
		rules.DevinPersonalAPIKey(),
		rules.DevinServiceAPIKey(),
		rules.DevinServiceUserToken(),
		rules.DevCycleClientSDKKey(),
		rules.DevCycleMobileSDKKey(),
		rules.DevCycleServerSDKKey(),
		rules.DigitalOceanPAT(),
		rules.DigitalOceanOAuthToken(),
		rules.DigitalOceanRefreshToken(),
		rules.DisqusAPIKey(),
		rules.DiscordAPIToken(),
		rules.DiscordClientID(),
		rules.DiscordClientSecret(),
		rules.Doppler(),
		rules.DockerHubPersonalAccessToken(),
		rules.DockerHubOrganizationAccessToken(),
		rules.DockerSwarmJoinToken(),
		rules.DockerSwarmUnlockKey(),
		rules.DropBoxAPISecret(),
		rules.DropBoxLongLivedAPIToken(),
		rules.DropBoxShortLivedAPIToken(),
		rules.DroneciAccessToken(),
		rules.Duffel(),
		rules.Dynatrace(),
		rules.EasyPost(),
		rules.ElasticCloudAPIKey(),
		rules.ElevenLabs(),
		rules.EndorLabsAPIKey(),
		rules.EndorLabsAPISecret(),
		rules.EasyPostTestAPI(),
		rules.EBayClientID(),
		rules.EBayClientSecret(),
		rules.EtsyAccessToken(),
		rules.ExoscaleAPIKey(),
		rules.ExoscaleAPISecret(),
		rules.FacebookSecret(),
		rules.FacebookAccessToken(),
		rules.FacebookPageAccessToken(),
		rules.FalAPIKey(),
		rules.FastlyAPIToken(),
		rules.FigmaPersonalAccessToken(),
		rules.FigmaPersonalAccessHeaderToken(),
		rules.FinicityClientSecret(),
		rules.FinicityAPIToken(),
		rules.FlickrAccessToken(),
		rules.FinnhubAccessToken(),
		rules.FlutterwavePublicKey(),
		rules.FlutterwaveSecretKey(),
		rules.FlutterwaveEncKey(),
		rules.FlyIOAccessToken(),
		rules.FrameIO(),
		rules.FullStoryAPIKey(),
		rules.Freemius(),
		rules.FreshbooksAccessToken(),
		rules.GoCardless(),
		rules.GCPApplicationDefaultCredentials(),
		rules.GCPServiceAccount(),
		rules.GCPAPIKey(),
		rules.GCPGeminiAPIKey(),
		rules.GCNotifyAPIKey(),
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
		rules.GitlabIncomingMailAddressToken(),
		rules.GitlabKubernetesAgentToken(),
		rules.GitlabOauthAppSecret(),
		rules.GitlabPat(),
		rules.GitlabPatRoutable(),
		rules.GitlabPatRoutableVersioned(),
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
		rules.GumroadAccessToken(),
		rules.HarnessApiKey(),
		rules.HashiCorpTerraform(),
		rules.HashicorpField(),
		rules.Heroku(),
		rules.HerokuV2(),
		rules.HighnoteSecretLiveKey(),
		rules.HoneycombAPIKey(),
		rules.HubSpot(),
		rules.HuggingFaceAccessToken(),
		rules.HuggingFaceOrganizationApiToken(),
		rules.HunterAPIKey(),
		rules.IBMCloudUserAPIKey(),
		rules.Infomaniak(),
		rules.InfluxDBAPIToken(),
		rules.InstantlyAPIKey(),
		rules.Intercom(),
		rules.Intra42ClientSecret(),
		rules.IonicPersonalAccessToken(),
		rules.JWT(),
		rules.JWTBase64(),
		rules.JumpCloudAPIKey(),
		rules.KagiAPIKey(),
		rules.KimiAPIKey(),
		rules.KlaviyoAPIKey(),
		rules.KrakenAccessToken(),
		rules.KubernetesSecret(),
		rules.KucoinAccessToken(),
		rules.KucoinSecretKey(),
		rules.LangfusePublicKey(),
		rules.LangfuseSecretKey(),
		rules.LangSmithPersonalAccessToken(),
		rules.LangSmithServiceKey(),
		rules.LarkAppID(),
		rules.LarkAppSecret(),
		rules.LaunchDarklyAccessToken(),
		rules.LichessPersonalAccessToken(),
		rules.LightOn(),
		rules.LlamaCloudAPIKey(),
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
		rules.MailerSendAPIToken(),
		rules.MapBox(),
		rules.Mistral(),
		rules.MattermostAccessToken(),
		rules.MaxMindLicenseKey(),
		rules.Mem0APIKey(),
		rules.Meraki(),
		rules.MercuryProductionAPIToken(),
		rules.MergifyApplicationKey(),
		rules.MessageBirdAPIToken(),
		rules.MessageBirdClientID(),
		rules.MidtransProductionServerClientKey(),
		rules.MiniMaxAPIKey(),
		rules.MiroAccessToken(),
		rules.MiroClientID(),
		rules.MiroClientSecret(),
		rules.MondayAPIToken(),
		rules.MongoDBAtlasServiceAccountID(),
		rules.MongoDBAtlasServiceAccountSecret(),
		rules.MongoDBConnectionString(),
		rules.MuxAccessTokenID(),
		rules.MuxAccessTokenSecret(),
		rules.NeonAPIKey(),
		// TODO: Enable NeonConnectionURI once Betterleaks has a PostgreSQL validator.
		// rules.NeonConnectionURI(),
		rules.NetlifyAccessToken(),
		rules.NgrokAPIKey(),
		rules.NewRelicUserID(),
		rules.NewRelicUserKey(),
		rules.NewRelicBrowserAPIKey(),
		rules.NewRelicInsertKey(),
		rules.Notion(),
		rules.NPM(),
		rules.NugetConfigPassword(),
		rules.NvidiaAPIKey(),
		rules.NylasAPIKey(),
		rules.NytimesAccessToken(),
		rules.Ollama(),
		rules.OctopusDeployApiKey(),
		rules.OneSignalRichAuthenticationToken(),
		rules.OpsgenieAPIKey(),
		rules.OnfidoLiveAPITokenCA(),
		rules.OnfidoLiveAPITokenEU(),
		rules.OnfidoLiveAPITokenUS(),
		rules.OpenWeatherAPIKey(),
		rules.OktaAccessToken(),
		rules.OpenAI(),
		rules.OpenRouter(),
		rules.OpenshiftUserToken(),
		rules.OVHApplicationKey(),
		rules.OVHConsumerKey(),
		rules.OVHApplicationSecret(),
		rules.PaddleLiveAPIKey(),
		rules.PagerDutyAuthorizationToken(),
		rules.PayPalClientID(),
		rules.PayPalClientSecret(),
		rules.PersonaProductionAPIKey(),
		rules.PerplexityAPIKey(),
		rules.PineconeAPIKeyV1(),
		rules.PineconeAPIKeyV2(),
		rules.PinterestAccessToken(),
		rules.PostHogProjectAPIKey(),
		rules.PostHogPersonalAPIKey(),
		rules.PostmarkAPIToken(),
		rules.PlaidAccessID(),
		rules.PlaidSecretKey(),
		rules.PlaidAccessToken(),
		rules.PlanetScalePassword(),
		rules.PlanetScaleAPIToken(),
		rules.PlanetScaleID(),
		rules.PlanetScaleOAuthToken(),
		rules.PlivoAuthID(),
		rules.PlivoAuthToken(),
		rules.PolymarketAPISecret(),
		rules.PolymarketPassphrase(),
		rules.PolymarketAddress(),
		rules.PolymarketAPIKey(),
		rules.PolymarketPrivateKey(),
		rules.PolarOrganizationAccessToken(),
		rules.PolarPersonalAccessToken(),
		rules.PolarOAuthAccessToken(),
		rules.PostManAPI(),
		rules.Prefect(),
		rules.PrivateAIToken(),
		rules.PrivateKey(),
		rules.PrivateKeyPKCS12File(),
		rules.ProofFullAccessAPIKey(),
		rules.PulumiAPIToken(),
		rules.PyPiUploadToken(),
		rules.RainforestPayProductionAPIKey(),
		rules.RampClientID(),
		rules.RampClientSecret(),
		rules.RapidAPIAccessToken(),
		rules.RazorpayKeyID(),
		rules.RazorpayKeySecret(),
		rules.ReadMe(),
		rules.RedirectPizzaAPIToken(),
		rules.RenderAPIKey(),
		rules.Replicate(),
		rules.ResendAPIKey(),
		rules.RetellAPIKey(),
		rules.RootlyAPIKey(),
		rules.RubyGemsAPIToken(),
		rules.RunPodAPIKey(),
		rules.SalesforceInstanceURL(),
		rules.SalesforceAccessToken(),
		rules.SamsaraAPIToken(),
		rules.ScalrAPIAccessToken(),
		rules.ScalewaySecretKey(),
		rules.ScalingoAPIToken(),
		rules.SegmentPublicAPIToken(),
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
		rules.SupabaseManagementToken(),
		rules.SupabaseProjectAPIKey(),
		rules.SupabaseProjectURL(),
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
		rules.SlackSessionCookie(),
		rules.SlackSessionToken(),
		rules.SlackWebHookUrl(),
		rules.SnowflakeAccountHost(),
		rules.SnowflakeProgrammaticAccessToken(),
		rules.Snyk(),
		rules.Sonar(),
		rules.SourceGraph(),
		rules.SSLMateAPIKey(),
		// rules.CfxreServerKey(), found in GHAS but imo not worth it to add it at this time.
		rules.CheckoutSecretKey(),
		rules.CircleCIPersonalToken(),
		rules.CircleCIProjectToken(),
		rules.CratesIOAPIKey(),
		rules.DatabentoAPIKey(),
		rules.StabilityAI(),
		rules.StripeAccessToken(),
		rules.SquareAccessToken(),
		rules.SquareSpaceAccessToken(),
		rules.SumoLogicAccessID(),
		rules.SumoLogicAccessToken(),
		rules.TableauPersonalAccessTokenName(),
		rules.TableauServerHost(),
		rules.TableauPersonalAccessToken(),
		rules.TailscaleAPIKey(),
		rules.TelnyxAPIV2Key(),
		rules.TeamsWebhook(),
		rules.TemporalCloudAPIKey(),
		rules.ThunderstoreAPIToken(),
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
		rules.UnkeyRootKey(),
		rules.UpCloud(),
		rules.Upstage(),
		rules.UpstashRedisRESTURL(),
		rules.UpstashRedisRESTToken(),
		rules.ValTownAPIToken(),
		rules.VercelAPIToken(),
		rules.VercelPersonalAccessToken(),
		rules.VercelIntegrationToken(),
		rules.VercelAppAccessToken(),
		rules.VercelAppRefreshToken(),
		rules.VercelAIGatewayKey(),
		rules.VaultBatchToken(),
		rules.VaultServiceToken(),
		rules.VirusTotalAPIKey(),
		rules.VultrAPIKey(),
		rules.WakaTimeAPIKeyV1(),
		rules.WakaTimeAPIKeyV2(),
		rules.WeatherstackAPIKey(),
		rules.WeightsAndBiases(),
		rules.WeightsAndBiasesV1(),
		rules.WizClientID(),
		rules.WizClientSecret(),
		rules.WooCommerceConsumerSecret(),
		rules.WorkatoDeveloperAPIToken(),
		rules.WorkOSProductionAPIKey(),
		rules.XAI(),
		rules.XenditProductionAPIKey(),
		rules.YandexAPIKey(),
		rules.YandexAWSAccessToken(),
		rules.YandexAccessToken(),
		rules.ZAIAPIKey(),
		rules.ZendeskSecretKey(),
		rules.ZohoOAuthToken(),
		rules.ZohoClientID(),
		rules.ZohoClientSecret(),
		rules.ZohoZAPIKey(),
		rules.ZuploConsumerAPIKey(),
		rules.GenericCredentialURI(),
		rules.GenericUsername(),
		rules.GenericPassword(),
		rules.GenericCredential(),
		rules.InfracostAPIToken(),
	}

	// ensure rules have unique ids
	ruleIDs := make(map[string]struct{}, len(configRules))
	ruleList := make([]config.Rule, 0, len(configRules))
	for _, rule := range configRules {
		if err := rule.Validate(); err != nil {
			logging.Fatal("Failed to validate rule", "error", err, "rule_id", rule.RuleID)
		}

		// check if rule is in ruleLookUp
		if _, ok := ruleIDs[rule.RuleID]; ok {
			logging.Fatal("rule id is not unique", "rule_id", rule.RuleID)
		}
		// TODO: eventually change all the signatures to get ride of this
		// nasty dereferencing.
		ruleIDs[rule.RuleID] = struct{}{}
		ruleList = append(ruleList, *rule)
	}
	// The template previously ranged over a map, which emitted string keys in
	// sorted order. Keep generated configs stable now that Rules is a slice.
	sort.Slice(ruleList, func(i, j int) bool {
		return ruleList[i].RuleID < ruleList[j].RuleID
	})

	funcMap := template.FuncMap{
		"tomlQuote": tomlQuote,
		"tomlExpr": func(s string) string {
			// Always use TOML multi-line literal strings for filter/prefilter
			// expressions. This avoids quoting issues and improves readability.
			return "'''\n" + s + "\n'''"
		},
		"tomlInlineTable": func(m map[string]string) string {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			parts := make([]string, 0, len(keys))
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%s = %s", tomlKeyQuote(k), tomlQuote(m[k])))
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
				parts = append(parts, fmt.Sprintf("%s = %s", tomlKeyQuote(k), tomlValue(m[k])))
			}
			return "{ " + strings.Join(parts, ", ") + " }"
		},
	}
	tmpl, err := template.New("config.tmpl").Funcs(funcMap).ParseFiles(templatePath)
	if err != nil {
		logging.Fatal("Failed to parse template", "error", err)
	}

	f, err := os.Create(betterleaksConfigPath)
	if err != nil {
		logging.Fatal("Failed to create rules.toml", "error", err)
	}
	defer f.Close()

	cfg := base.CreateGlobalConfig()
	cfg.Rules = ruleList

	if err = tmpl.Execute(f, cfg); err != nil {
		logging.Fatal("could not execute template", "error", err)
	}
}
