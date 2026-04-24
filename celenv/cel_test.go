package celenv

import (
	"testing"
)

// celExpressions contains every ValidateCEL expression used across the rule
// files. The test compiles each one against the real CEL environment to catch
// syntax errors and unknown function references before go generate is run.
var celExpressions = []struct {
	name string
	expr string
}{
	{
		"anthropic-api-key",
		`cel.bind(r,
  http.get("https://api.anthropic.com/v1/models", {
    "x-api-key": secret,
    "anthropic-version": "2023-06-01"
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	},
	{
		"anthropic-admin-api-key",
		`cel.bind(r,
  http.get("https://api.anthropic.com/v1/organizations/me", {
    "x-api-key": secret,
    "anthropic-version": "2023-06-01"
  }),
  r.status == 200 ? {
    "result": "valid",
    "organization": r.json.?name.orValue("")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	},
	{
		"cerebras-api-key",
		`cel.bind(r,
  http.get("https://api.cerebras.ai/v1/models", {
    "Authorization": "Bearer " + secret
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	},
	{
		"cohere-api-token",
		`cel.bind(r,
  http.get("https://api.cohere.com/v1/connectors", {
    "Authorization": "Bearer " + secret
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	},
	{
		"cursor-api-key",
		`cel.bind(r,
  http.get("https://api.cursor.com/v0/me", {
    "Accept": "application/json",
    "Authorization": "Basic " + base64.encode(bytes(secret))
  }),
  r.status == 200 && r.body.contains('"userEmail"') ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	},
	{
		"deepseek-api-key",
		`cel.bind(r,
  http.get("https://api.deepseek.com/models", {
    "Authorization": "Bearer " + secret,
    "Accept": "application/json"
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	},
	{
		"github-pat",
		`cel.bind(r,
  http.get("https://api.github.com/user", {
    "Accept": "application/vnd.github+json",
    "Authorization": "token " + secret
  }),
  r.status == 200 ? {
    "result": "valid",
    "username": r.json.?login.orValue(""),
    "name": r.json.?name.orValue(""),
    "scopes": r.headers[?"x-oauth-scopes"].orValue("")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	},
	{
		"gitlab-user-token",
		`cel.bind(r,
  http.get("https://gitlab.com/api/v4/user", {
    "PRIVATE-TOKEN": secret
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	},
	{
		"gitlab-pat",
		`cel.bind(r,
  http.get("https://gitlab.com/api/v4/personal_access_tokens/self", {
    "PRIVATE-TOKEN": secret
  }),
  r.status == 200 ? {
    "result": "valid",
    "name": r.json.?name.orValue("")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	},
	{
		"gitlab-runner-registration",
		`cel.bind(r,
  http.post("https://gitlab.com/api/v4/runners/verify", {
    "Content-Type": "application/x-www-form-urlencoded"
  }, "token=" + secret),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	},
	{
		"groq-api-key",
		`cel.bind(r,
  http.get("https://api.groq.com/openai/v1/models", {
    "Authorization": "Bearer " + secret
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	},
	{
		"huggingface-access-token",
		`cel.bind(r,
  http.get("https://huggingface.co/api/whoami-v2", {
    "Authorization": "Bearer " + secret
  }),
  r.status == 200 ? {
    "result": "valid",
    "username": r.json.?name.orValue("")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	},
	{
		"mailchimp-api-key",
		`cel.bind(dc, secret.substring(secret.lastIndexOf("-") + 1),
  cel.bind(r,
    http.get("https://" + dc + ".api.mailchimp.com/3.0/ping", {
      "Accept": "application/json",
      "Authorization": "Basic " + base64.encode(bytes("x:" + secret))
    }),
    r.status == 200 ? {
      "result": "valid"
    } : r.status in [401, 403] ? {
      "result": "invalid",
      "reason": "Unauthorized"
    } : unknown(r)
  )
)`,
	},
	{
		"mailgun-private-api-token",
		`cel.bind(r,
  http.get("https://api.mailgun.net/v3/domains", {
    "Accept": "application/json",
    "Authorization": "Basic " + base64.encode(bytes("api:" + secret))
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	},
	{
		"mistral-api-key",
		`cel.bind(r,
  http.get("https://api.mistral.ai/v1/models", {
    "Authorization": "Bearer " + secret,
    "Accept": "application/json"
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	},
	{
		"openai-api-key",
		`cel.bind(r,
  http.get("https://api.openai.com/v1/models", {
    "Authorization": "Bearer " + secret
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	},
	{
		"perplexity-api-key",
		`cel.bind(r,
  http.post("https://api.perplexity.ai/chat/completions", {
    "Authorization": "Bearer " + secret,
    "Content-Type": "application/json"
  }, "{\"model\":\"invalid-model-for-validation\",\"messages\":[{\"role\":\"user\",\"content\":\".\"}]}"),
  r.status in [200, 400, 404, 422] ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	},
	{
		"replicate-api-token",
		`cel.bind(r,
  http.get("https://api.replicate.com/v1/account", {
    "Authorization": "Bearer " + secret
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	},
	{
		"togetherai-api-key",
		`cel.bind(r,
  http.get("https://api.together.xyz/v1/models", {
    "Authorization": "Bearer " + secret,
    "Accept": "application/json"
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	},
	{
		"polymarket-api-key",
		`cel.bind(ts, time.now_unix(),
  cel.bind(sig,
    crypto.hmac_sha256(
      base64.decode(captures["polymarket-api-secret"]),
      bytes(ts + "GET" + "/data/orders")
    ),
    cel.bind(r,
      http.get("https://clob.polymarket.com/data/orders", {
        "POLY_BUILDER_API_KEY": secret,
        "POLY_BUILDER_PASSPHRASE": captures["polymarket-passphrase"],
        "POLY_BUILDER_TIMESTAMP": ts,
        "POLY_BUILDER_SIGNATURE": base64.encode(sig).replace("+", "-").replace("/", "_")
      }),
      r.status == 200 ? {
        "result": "valid"
      } : r.status in [401, 403] ? {
        "result": "invalid",
        "reason": "Unauthorized"
      } : unknown(r)
    )
  )
)`,
	},
	{
		"weights-and-biases-api-key",
		`cel.bind(r,
  http.post("https://api.wandb.ai/graphql", {
    "Authorization": "Basic " + base64.encode(bytes("api:" + secret)),
    "Content-Type": "application/json"
  }, "{\"query\":\"query { viewer { email username } }\"}"),
  r.status == 200 && r.body.contains("\"username\"") ? {
    "result": "valid",
    "email": r.json.?data.?viewer.?email.orValue(""),
    "username": r.json.?data.?viewer.?username.orValue("")
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : unknown(r)
)`,
	},
	{
		"ovh-application-secret",
		`cel.bind(ts, string(time.now_unix()),
  cel.bind(url, "https://api.us.ovhcloud.com/1.0/auth/details",
    cel.bind(sig_payload, secret + "+" + captures["ovh-consumer-key"] + "+GET+" + url + "++" + ts,
      cel.bind(sig, "$1$" + hex.encode(crypto.sha1(bytes(sig_payload))),
        cel.bind(r,
          http.get(url, {
            "X-Ovh-Application": captures["ovh-application-key"],
            "X-Ovh-Consumer": captures["ovh-consumer-key"],
            "X-Ovh-Timestamp": ts,
            "X-Ovh-Signature": sig
          }),
          r.status == 200 ? {
            "result": "valid"
          } : r.status in [400, 401, 403] ? {
            "result": "invalid",
            "reason": "Unauthorized"
          } : unknown(r)
        )
      )
    )
  )
)`,
	},
}

func TestCELExpressionsCompile(t *testing.T) {
	env, err := NewEnvironment(nil)
	if err != nil {
		t.Fatalf("NewEnvironment: %v", err)
	}

	for _, tc := range celExpressions {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := env.Compile(tc.expr); err != nil {
				t.Errorf("compile error: %v", err)
			}
		})
	}
}
