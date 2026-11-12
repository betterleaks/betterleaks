package rules

import (
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
)

var _ = rulebuilder.Add(config.Rule{
	ID:          "mongodb-atlas-service-account-secret",
	Confidence:  "high",
	Description: "Detected a MongoDB Atlas service account client secret, which could allow unauthorized Atlas administration API access when paired with a service account client ID.",
	Regex:       rulebuilder.Token(`mdb_sa_sk_[A-Za-z0-9_-]{40}`),
	Keywords:    []string{"mdb_sa_sk_"},
	Components: []config.Component{
		{RuleID: "mongodb-atlas-service-account-id"},
	},
	ValidateExpr: `let r = http.post("https://cloud.mongodb.com/api/oauth/token", {
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
    "Authorization": "Basic " + base64.encode(bytes((components["mongodb-atlas-service-account-id"]?.secret ?? "") + ":" + finding["secret"]))
  }, "grant_type=client_credentials"); r.status == 200 && (r.json?.access_token ?? "") != "" ? {
    "result": "valid"
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": (r.json?.error ?? "Unauthorized")
  } : validate.unknown(r)`,
	FilterExpr: "entropy(finding[\"secret\"]) <= 3.0\n|| matchesAny(finding[\"secret\"], [`^mdb_sa_sk_[0-9]{40}$`])",
	Tests: []config.RuleTest{
		{
			Name:  "assignment",
			Input: "mongodbAtlasServiceAccountToken = \"mdb_sa_sk_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7li\"\nmongodbAtlasServiceAccountIdToken = \"mdb_sa_id_1f7b169c846f218ab552fa82\"",
			Expect: []config.ExpectedFinding{
				{Secret: "mdb_sa_sk_5fbbd6p84oe7ut4qrttebiwar77s63donnl8x7li", ComponentSets: []map[string]string{{"mongodb-atlas-service-account-id": "mdb_sa_id_1f7b169c846f218ab552fa82"}}},
			},
		},
		{
			Name:  "true positive 1",
			Input: "export MDB_MCP_API_CLIENT_SECRET=\"mdb_sa_sk_5fbbd6p84oe7ut4qrt_-5fbbd6p84oe7ut4qrtte\"\nmongodbAtlasServiceAccountIdToken = \"mdb_sa_id_1f7b169c846f218ab552fa82\"",
			Expect: []config.ExpectedFinding{
				{Secret: "mdb_sa_sk_5fbbd6p84oe7ut4qrt_-5fbbd6p84oe7ut4qrtte", ComponentSets: []map[string]string{{"mongodb-atlas-service-account-id": "mdb_sa_id_1f7b169c846f218ab552fa82"}}},
			},
		},
		{
			Name:  "true positive 2",
			Input: "MDB_ATLAS_SERVICE_ACCOUNT_SECRET='mdb_sa_sk_5fbbd6p84oe7-5fbbd6p84oe7ut4qrttebiwar77'\nmongodbAtlasServiceAccountIdToken = \"mdb_sa_id_1f7b169c846f218ab552fa82\"",
			Expect: []config.ExpectedFinding{
				{Secret: "mdb_sa_sk_5fbbd6p84oe7-5fbbd6p84oe7ut4qrttebiwar77", ComponentSets: []map[string]string{{"mongodb-atlas-service-account-id": "mdb_sa_id_1f7b169c846f218ab552fa82"}}},
			},
		},
		{
			Name:  "true positive 3",
			Input: "clientSecret: \"mdb_sa_sk_5fbbd6p84oe7ut4_5fbbd6p84oe7ut4qrttebiwa\"\nmongodbAtlasServiceAccountIdToken = \"mdb_sa_id_1f7b169c846f218ab552fa82\"",
			Expect: []config.ExpectedFinding{
				{Secret: "mdb_sa_sk_5fbbd6p84oe7ut4_5fbbd6p84oe7ut4qrttebiwa", ComponentSets: []map[string]string{{"mongodb-atlas-service-account-id": "mdb_sa_id_1f7b169c846f218ab552fa82"}}},
			},
		},
		rulebuilder.NoMatch("false positive 1", "atlas api serviceAccounts getServiceAccount --clientId mdb_sa_id_1234567890abcdef12345678 --orgId 4888442a3354817a7320eb61"),
		rulebuilder.NoMatch("false positive 2", `export MDB_MCP_API_CLIENT_SECRET="mdb_sa_sk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`),
		rulebuilder.NoMatch("false positive 3", `export MDB_MCP_API_CLIENT_SECRET="mdb_sa_sk_1234567890123456789012345678901234567890"`),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "mongodb-atlas-service-account-id",
	Confidence:  "high",
	Description: "Found a MongoDB Atlas service account client ID.",
	Regex:       rulebuilder.Token(`mdb_sa_id_[a-f0-9]{24}`),
	Keywords:    []string{"mdb_sa_id_"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		rulebuilder.MatchComponent("assignment", `mongodbAtlasServiceAccountIdToken = "mdb_sa_id_1f7b169c846f218ab552fa82"`, "mdb_sa_id_1f7b169c846f218ab552fa82"),
	},
})

var _ = rulebuilder.Add(config.Rule{
	ID:          "mongodb-connection-string",
	Confidence:  "high",
	Description: "Detected a MongoDB connection string with embedded credentials, potentially exposing direct database access and sensitive application data.",
	Regex:       `\b(mongodb(?:\+srv)?://(?P<username>[!-9;-~]{3,50}):(?P<password>[!-?A-~]{3,88})@(?P<host>(?:[a-zA-Z0-9][\w.-]+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d{1,5})?(?:,(?:[a-zA-Z0-9][\w.-]+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d{1,5})?)*)/?(?:(?P<authdb>[\w-]+)?(?P<options>\?\w+=[\w@/.$-]+(?:&(?:amp;)?\w+=[\w@/.$-]+)*)?)?)(?:['"\s;\x60]|\\[nr]|\b|$)`,
	Keywords:    []string{"mongodb://", "mongodb+srv://"},
	FilterExpr:  "entropy(finding[\"secret\"]) <= 4.0\n|| matchesAny(finding[\"secret\"], [\n  `(?i)\\bmongodb(?:\\+srv)?:\\/\\/(?:user(?:name)?|foo):(?:pass(?:word)?|bar)(?:[^@\\/]*)?@`,\n  `(?i)\\bmongodb(?:\\+srv)?:\\/\\/[^\\s'\"\\x60]*(?:\\$\\{\\{[^}]+}}|\\$\\{[^}]+}|\\$[A-Za-z_][A-Za-z0-9_]*|{{[^}]+}}|<[^>]+>|\\[[^]]+])[^\\s'\"\\x60]*`\n])",
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: `MONGODB_URI="mongodb+srv://app-user:q9V7nB2K4xL8@cluster0.mongodb.net/sample_mflix?retryWrites=true&w=majority"`,
			Expect: []config.ExpectedFinding{
				{Secret: "mongodb+srv://app-user:q9V7nB2K4xL8@cluster0.mongodb.net/sample_mflix?retryWrites=true&w=majority", Captures: map[string]string{"authdb": "sample_mflix", "host": "cluster0.mongodb.net", "options": "?retryWrites=true&w=majority", "password": "q9V7nB2K4xL8", "username": "app-user"}},
			},
		},
		{
			Name:  "true positive 2",
			Input: "spring.data.mongodb.uri=mongodb://svc-reader:Az9xV2pLm6Q@mongo1.internal.example:27017,mongo2.internal.example:27017/app?replicaSet=rs0&authSource=admin",
			Expect: []config.ExpectedFinding{
				{Secret: "mongodb://svc-reader:Az9xV2pLm6Q@mongo1.internal.example:27017,mongo2.internal.example:27017/app?replicaSet=rs0&authSource=admin", Captures: map[string]string{"authdb": "app", "host": "mongo1.internal.example:27017,mongo2.internal.example:27017", "options": "?replicaSet=rs0&authSource=admin", "password": "Az9xV2pLm6Q", "username": "svc-reader"}},
			},
		},
		{
			Name:  "true positive 3",
			Input: "mongo_url: 'mongodb://backup-user:p%40ssw0rd123@db.example.com:27017/admin'",
			Expect: []config.ExpectedFinding{
				{Secret: "mongodb://backup-user:p%40ssw0rd123@db.example.com:27017/admin", Captures: map[string]string{"authdb": "admin", "host": "db.example.com:27017", "password": "p%40ssw0rd123", "username": "backup-user"}},
			},
		},
		{
			Name:  "true positive 4",
			Input: "export MONGO_URL=mongodb://reader-user:Qv8h2Lp4Rk7m@db-shard-00.example.net:27017/app?authSource=admin",
			Expect: []config.ExpectedFinding{
				{Secret: "mongodb://reader-user:Qv8h2Lp4Rk7m@db-shard-00.example.net:27017/app?authSource=admin", Captures: map[string]string{"authdb": "app", "host": "db-shard-00.example.net:27017", "options": "?authSource=admin", "password": "Qv8h2Lp4Rk7m", "username": "reader-user"}},
			},
		},
		{
			Name:  "true positive 5",
			Input: `MONGO_URL="mongodb+srv://deploy-user:Xk9mP3vN7qR2@cluster0.mongodb.net/"`,
			Expect: []config.ExpectedFinding{
				{Secret: "mongodb+srv://deploy-user:Xk9mP3vN7qR2@cluster0.mongodb.net/", Captures: map[string]string{"host": "cluster0.mongodb.net", "password": "Xk9mP3vN7qR2", "username": "deploy-user"}},
			},
		},
		rulebuilder.NoMatch("false positive 1", `MONGODB_URI="mongodb://user:pass@localhost:27017/app"`),
		rulebuilder.NoMatch("false positive 2", "spring.data.mongodb.uri=mongodb+srv://<username>:<password>@cluster.mongodb.net/app"),
		rulebuilder.NoMatch("false positive 3", "mongodb://$MONGODB_USER:$MONGODB_PASSWORD@cluster.mongodb.net/app"),
		rulebuilder.NoMatch("false positive 4", "mongodb+srv://${DB_USER}:${DB_PASS}@cluster.mongodb.net/"),
		rulebuilder.NoMatch("false positive 5", "mongodb://{{ .Values.mongoUser }}:{{ .Values.mongoPassword }}@mongo.example.net/app"),
	},
})
