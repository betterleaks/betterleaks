package main

import (
	"os"
	"slices"
	"text/template"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/config/generate/base"
	rules2 "github.com/betterleaks/betterleaks/config/generate/rules"
	"github.com/betterleaks/betterleaks/logging"
)

const (
	templatePath = "rules/config.tmpl"
)

//go:generate go run $GOFILE ../gitleaks.toml

func main() {
	if len(os.Args) < 2 {
		_, _ = os.Stderr.WriteString("Specify path to the gitleaks.toml config\n")
		os.Exit(2)
	}
	gitleaksConfigPath := os.Args[1]

	configRules := []*config.Rule{
		rules2.OnePasswordSecretKey(),
		rules2.OnePasswordServiceAccountToken(),
		rules2.AdafruitAPIKey(),
		rules2.AdobeClientID(),
		rules2.AdobeClientSecret(),
		rules2.AgeSecretKey(),
		rules2.AirtableApiKey(),
		rules2.AirtablePersonalAccessToken(),
		rules2.AlgoliaApiKey(),
		rules2.AlibabaAccessKey(),
		rules2.AlibabaSecretKey(),
		rules2.AmazonBedrockAPIKeyLongLived(),
		rules2.AmazonBedrockAPIKeyShortLived(),
		rules2.AnthropicAdminApiKey(),
		rules2.AnthropicApiKey(),
		rules2.ArtifactoryApiKey(),
		rules2.ArtifactoryReferenceToken(),
		rules2.AsanaClientID(),
		rules2.AsanaClientSecret(),
		rules2.Atlassian(),
		rules2.Authress(),
		rules2.AWS(),
		rules2.AzureActiveDirectoryClientSecret(),
		rules2.BitBucketClientID(),
		rules2.BitBucketClientSecret(),
		rules2.BittrexAccessKey(),
		rules2.BittrexSecretKey(),
		rules2.Beamer(),
		rules2.CodecovAccessToken(),
		rules2.CoinbaseAccessToken(),
		rules2.ClickHouseCloud(),
		rules2.Clojars(),
		rules2.CloudflareAPIKey(),
		rules2.CloudflareGlobalAPIKey(),
		rules2.CloudflareOriginCAKey(),
		rules2.CohereAPIToken(),
		rules2.ConfluentAccessToken(),
		rules2.ConfluentSecretKey(),
		rules2.Contentful(),
		rules2.CurlHeaderAuth(),
		rules2.CurlBasicAuth(),
		rules2.Databricks(),
		rules2.DatadogtokenAccessToken(),
		rules2.DefinedNetworkingAPIToken(),
		rules2.DigitalOceanPAT(),
		rules2.DigitalOceanOAuthToken(),
		rules2.DigitalOceanRefreshToken(),
		rules2.DiscordAPIToken(),
		rules2.DiscordClientID(),
		rules2.DiscordClientSecret(),
		rules2.Doppler(),
		rules2.DropBoxAPISecret(),
		rules2.DropBoxLongLivedAPIToken(),
		rules2.DropBoxShortLivedAPIToken(),
		rules2.DroneciAccessToken(),
		rules2.Duffel(),
		rules2.Dynatrace(),
		rules2.EasyPost(),
		rules2.EasyPostTestAPI(),
		rules2.EtsyAccessToken(),
		rules2.FacebookSecret(),
		rules2.FacebookAccessToken(),
		rules2.FacebookPageAccessToken(),
		rules2.FastlyAPIToken(),
		rules2.FinicityClientSecret(),
		rules2.FinicityAPIToken(),
		rules2.FlickrAccessToken(),
		rules2.FinnhubAccessToken(),
		rules2.FlutterwavePublicKey(),
		rules2.FlutterwaveSecretKey(),
		rules2.FlutterwaveEncKey(),
		rules2.FlyIOAccessToken(),
		rules2.FrameIO(),
		rules2.Freemius(),
		rules2.FreshbooksAccessToken(),
		rules2.GoCardless(),
		// TODO figure out what makes sense for GCP
		// rules.GCPServiceAccount(),
		rules2.GCPAPIKey(),
		rules2.GitHubPat(),
		rules2.GitHubFineGrainedPat(),
		rules2.GitHubOauth(),
		rules2.GitHubApp(),
		rules2.GitHubRefresh(),
		rules2.GitlabCiCdJobToken(),
		rules2.GitlabDeployToken(),
		rules2.GitlabFeatureFlagClientToken(),
		rules2.GitlabFeedToken(),
		rules2.GitlabIncomingMailToken(),
		rules2.GitlabKubernetesAgentToken(),
		rules2.GitlabOauthAppSecret(),
		rules2.GitlabPat(),
		rules2.GitlabPatRoutable(),
		rules2.GitlabPipelineTriggerToken(),
		rules2.GitlabRunnerRegistrationToken(),
		rules2.GitlabRunnerAuthenticationToken(),
		rules2.GitlabRunnerAuthenticationTokenRoutable(),
		rules2.GitlabScimToken(),
		rules2.GitlabSessionCookie(),
		rules2.GitterAccessToken(),
		rules2.GrafanaApiKey(),
		rules2.GrafanaCloudApiToken(),
		rules2.GrafanaServiceAccountToken(),
		rules2.HarnessApiKey(),
		rules2.HashiCorpTerraform(),
		rules2.HashicorpField(),
		rules2.Heroku(),
		rules2.HerokuV2(),
		rules2.HubSpot(),
		rules2.HuggingFaceAccessToken(),
		rules2.HuggingFaceOrganizationApiToken(),
		rules2.Intercom(),
		rules2.Intra42ClientSecret(),
		rules2.JFrogAPIKey(),
		rules2.JFrogIdentityToken(),
		rules2.JWT(),
		rules2.JWTBase64(),
		rules2.KrakenAccessToken(),
		rules2.KubernetesSecret(),
		rules2.KucoinAccessToken(),
		rules2.KucoinSecretKey(),
		rules2.LaunchDarklyAccessToken(),
		rules2.LinearAPIToken(),
		rules2.LinearClientSecret(),
		rules2.LinkedinClientID(),
		rules2.LinkedinClientSecret(),
		rules2.LobAPIToken(),
		rules2.LobPubAPIToken(),
		rules2.LookerClientID(),
		rules2.LookerClientSecret(),
		rules2.MailChimp(),
		rules2.MailGunPubAPIToken(),
		rules2.MailGunPrivateAPIToken(),
		rules2.MailGunSigningKey(),
		rules2.MapBox(),
		rules2.MattermostAccessToken(),
		rules2.MaxMindLicenseKey(),
		rules2.Meraki(),
		rules2.MessageBirdAPIToken(),
		rules2.MessageBirdClientID(),
		rules2.NetlifyAccessToken(),
		rules2.NewRelicUserID(),
		rules2.NewRelicUserKey(),
		rules2.NewRelicBrowserAPIKey(),
		rules2.NewRelicInsertKey(),
		rules2.Notion(),
		rules2.NPM(),
		rules2.NugetConfigPassword(),
		rules2.NytimesAccessToken(),
		rules2.OctopusDeployApiKey(),
		rules2.OktaAccessToken(),
		rules2.OpenAI(),
		rules2.OpenshiftUserToken(),
		rules2.PerplexityAPIKey(),
		rules2.PlaidAccessID(),
		rules2.PlaidSecretKey(),
		rules2.PlaidAccessToken(),
		rules2.PlanetScalePassword(),
		rules2.PlanetScaleAPIToken(),
		rules2.PlanetScaleOAuthToken(),
		rules2.PostManAPI(),
		rules2.Prefect(),
		rules2.PrivateAIToken(),
		rules2.PrivateKey(),
		rules2.PrivateKeyPKCS12File(),
		rules2.PulumiAPIToken(),
		rules2.PyPiUploadToken(),
		rules2.RapidAPIAccessToken(),
		rules2.ReadMe(),
		rules2.RubyGemsAPIToken(),
		rules2.ScalingoAPIToken(),
		rules2.SendbirdAccessID(),
		rules2.SendbirdAccessToken(),
		rules2.SendGridAPIToken(),
		rules2.SendInBlueAPIToken(),
		rules2.SentryAccessToken(),
		rules2.SentryOrgToken(),
		rules2.SentryUserToken(),
		rules2.SettlemintApplicationAccessToken(),
		rules2.SettlemintPersonalAccessToken(),
		rules2.SettlemintServiceAccessToken(),
		rules2.ShippoAPIToken(),
		rules2.ShopifyAccessToken(),
		rules2.ShopifyCustomAccessToken(),
		rules2.ShopifyPrivateAppAccessToken(),
		rules2.ShopifySharedSecret(),
		rules2.SidekiqSecret(),
		rules2.SidekiqSensitiveUrl(),
		rules2.SlackBotToken(),
		rules2.SlackUserToken(),
		rules2.SlackAppLevelToken(),
		rules2.SlackConfigurationToken(),
		rules2.SlackConfigurationRefreshToken(),
		rules2.SlackLegacyBotToken(),
		rules2.SlackLegacyWorkspaceToken(),
		rules2.SlackLegacyToken(),
		rules2.SlackWebHookUrl(),
		rules2.Snyk(),
		rules2.Sonar(),
		rules2.SourceGraph(),
		rules2.StripeAccessToken(),
		rules2.SquareAccessToken(),
		rules2.SquareSpaceAccessToken(),
		rules2.SumoLogicAccessID(),
		rules2.SumoLogicAccessToken(),
		rules2.TeamsWebhook(),
		rules2.TelegramBotToken(),
		rules2.TravisCIAccessToken(),
		rules2.Twilio(),
		rules2.TwitchAPIToken(),
		rules2.TwitterAPIKey(),
		rules2.TwitterAPISecret(),
		rules2.TwitterAccessToken(),
		rules2.TwitterAccessSecret(),
		rules2.TwitterBearerToken(),
		rules2.Typeform(),
		rules2.VaultBatchToken(),
		rules2.VaultServiceToken(),
		rules2.YandexAPIKey(),
		rules2.YandexAWSAccessToken(),
		rules2.YandexAccessToken(),
		rules2.ZendeskSecretKey(),
		rules2.GenericCredential(),
		rules2.InfracostAPIToken(),
	}

	// ensure rules have unique ids
	ruleLookUp := make(map[string]config.Rule, len(configRules))
	for _, rule := range configRules {
		if err := rule.Validate(); err != nil {
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

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		logging.Fatal().Err(err).Msg("Failed to parse template")
	}

	f, err := os.Create(gitleaksConfigPath)
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
