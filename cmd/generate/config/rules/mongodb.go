package rules

import (
	"strings"

	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func MongoDBAtlasServiceAccountSecret() *config.Rule {
	r := config.Rule{
		RuleID:      "mongodb-atlas-service-account-secret",
		Description: "Detected a MongoDB Atlas service account client secret, which could allow unauthorized Atlas administration API access when paired with a service account client ID.",
		Regex:       utils.GenerateUniqueTokenRegex(`mdb_sa_sk_[A-Za-z0-9_-]{40}`, false),
		Entropy:     3,
		Keywords:    []string{"mdb_sa_sk_"},
		RequiredRules: []*config.Required{
			{RuleID: "mongodb-atlas-service-account-id"},
		},
		ValidateCEL: `cel.bind(r,
  http.post("https://cloud.mongodb.com/api/oauth/token", {
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
    "Authorization": "Basic " + base64.encode(bytes(captures["mongodb-atlas-service-account-id"] + ":" + secret))
  }, "grant_type=client_credentials"),
  r.status == 200 && r.json.?access_token.orValue("") != "" ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": r.json.?error.orValue("Unauthorized")
  } : unknown(r)
)`,
		Allowlists: []*config.Allowlist{
			{
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`^mdb_sa_sk_[0-9]{40}$`),
				},
			},
		},
	}

	tps := utils.GenerateSampleSecrets("mongodbAtlasServiceAccount", "mdb_sa_sk_"+secrets.NewSecret(utils.AlphaNumeric("40")))
	tps = append(tps,
		`export MDB_MCP_API_CLIENT_SECRET="mdb_sa_sk_`+secrets.NewSecret(utils.AlphaNumeric("18"))+`_-`+secrets.NewSecret(utils.AlphaNumeric("20"))+`"`,
		`MDB_ATLAS_SERVICE_ACCOUNT_SECRET='mdb_sa_sk_`+secrets.NewSecret(utils.AlphaNumeric("12"))+`-`+secrets.NewSecret(utils.AlphaNumeric("27"))+`'`,
		`clientSecret: "mdb_sa_sk_`+secrets.NewSecret(utils.AlphaNumeric("15"))+`_`+secrets.NewSecret(utils.AlphaNumeric("24"))+`"`,
	)
	fps := []string{
		`atlas api serviceAccounts getServiceAccount --clientId mdb_sa_id_1234567890abcdef12345678 --orgId 4888442a3354817a7320eb61`,
		`export MDB_MCP_API_CLIENT_SECRET="mdb_sa_sk_` + strings.Repeat("x", 40) + `"`,
		`export MDB_MCP_API_CLIENT_SECRET="mdb_sa_sk_` + strings.Repeat("1234567890", 4) + `"`,
	}

	return utils.Validate(r, tps, fps)
}

func MongoDBAtlasServiceAccountID() *config.Rule {
	r := config.Rule{
		RuleID:      "mongodb-atlas-service-account-id",
		Description: "Found a MongoDB Atlas service account client ID.",
		Regex:       utils.GenerateUniqueTokenRegex(`mdb_sa_id_[a-f0-9]{24}`, false),
		Entropy:     3,
		Keywords:    []string{"mdb_sa_id_"},
		SkipReport:  true,
	}

	tps := utils.GenerateSampleSecrets("mongodbAtlasServiceAccountId", "mdb_sa_id_"+secrets.NewSecret(utils.Hex("24")))
	return utils.Validate(r, tps, nil)
}

func MongoDBConnectionString() *config.Rule {
	r := config.Rule{
		RuleID:      "mongodb-connection-string",
		Description: "Detected a MongoDB connection string with embedded credentials, potentially exposing direct database access and sensitive application data.",
		Regex:       regexp.MustCompile(`\b(mongodb(?:\+srv)?://(?P<username>[!-9;-~]{3,50}):(?P<password>[!-?A-~]{3,88})@(?P<host>(?:[a-zA-Z0-9][\w.-]+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d{1,5})?(?:,(?:[a-zA-Z0-9][\w.-]+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d{1,5})?)*)/?(?:(?P<authdb>[\w-]+)?(?P<options>\?\w+=[\w@/.$-]+(?:&(?:amp;)?\w+=[\w@/.$-]+)*)?)?)(?:['"\s;\x60]|\\[nr]|\b|$)`),
		Keywords:    []string{"mongodb://", "mongodb+srv://"},
		Entropy:     4,
		Allowlists: []*config.Allowlist{
			{
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`(?i)\bmongodb(?:\+srv)?:\/\/(?:user(?:name)?|foo):(?:pass(?:word)?|bar)(?:[^@\/]*)?@`),
					regexp.MustCompile(`(?i)\bmongodb(?:\+srv)?:\/\/[^\s'"\x60]*(?:\$\{\{[^}]+}}|\$\{[^}]+}|\$[A-Za-z_][A-Za-z0-9_]*|{{[^}]+}}|<[^>]+>|\[[^]]+])[^\s'"\x60]*`),
				},
			},
		},
	}

	tps := []string{
		`MONGODB_URI="mongodb+srv://app-user:q9V7nB2K4xL8@cluster0.mongodb.net/sample_mflix?retryWrites=true&w=majority"`,
		`spring.data.mongodb.uri=mongodb://svc-reader:Az9xV2pLm6Q@mongo1.internal.example:27017,mongo2.internal.example:27017/app?replicaSet=rs0&authSource=admin`,
		`mongo_url: 'mongodb://backup-user:p%40ssw0rd123@db.example.com:27017/admin'`,
		`export MONGO_URL=mongodb://reader-user:Qv8h2Lp4Rk7m@db-shard-00.example.net:27017/app?authSource=admin`,
		`MONGO_URL="mongodb+srv://deploy-user:Xk9mP3vN7qR2@cluster0.mongodb.net/"`,
	}
	fps := []string{
		`MONGODB_URI="mongodb://user:pass@localhost:27017/app"`,
		`spring.data.mongodb.uri=mongodb+srv://<username>:<password>@cluster.mongodb.net/app`,
		`mongodb://$MONGODB_USER:$MONGODB_PASSWORD@cluster.mongodb.net/app`,
		`mongodb+srv://${DB_USER}:${DB_PASS}@cluster.mongodb.net/`,
		`mongodb://{{ .Values.mongoUser }}:{{ .Values.mongoPassword }}@mongo.example.net/app`,
	}
	return utils.Validate(r, tps, fps)
}
