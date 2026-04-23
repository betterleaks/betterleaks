package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func OVHApplicationKey() *config.Rule {
	r := config.Rule{
		RuleID:      "ovh-application-key",
		Description: "OVHcloud Application Key - component of authenticated OVH API requests.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"app(?:lication)?[_.-]{0,1}key"}, `[A-Za-z0-9-]{16}`, true),
		Keywords:    []string{"ovh"},
		Entropy:     2,
		SkipReport:  true,
	}

	tps := []string{
		`ovh_application_key = "` + secrets.NewSecretWithEntropy(`[A-Za-z0-9-]{16}`, 3) + `"`,
		`ovh_applicationKey: "` + secrets.NewSecretWithEntropy(`[A-Za-z0-9-]{16}`, 3) + `"`,
		`OVH_APPLICATION_KEY="` + secrets.NewSecretWithEntropy(`[A-Za-z0-9-]{16}`, 3) + `"`,
	}
	fps := []string{
		`application_key = "short-key"`,
		`OVH_APPLICATION_KEY="<your-ovh-application-key>"`,
	}

	return utils.Validate(r, tps, fps)
}

func OVHConsumerKey() *config.Rule {
	r := config.Rule{
		RuleID:      "ovh-consumer-key",
		Description: "OVHcloud Consumer Key - component of authenticated OVH API requests.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"consumer[_.-]{0,1}key"}, `[A-Za-z0-9-]{32}`, true),
		Keywords:    []string{"ovh"},
		Entropy:     2,
		SkipReport:  true,
	}

	tps := []string{
		`ovh_consumer_key = "` + secrets.NewSecretWithEntropy(`[A-Za-z0-9-]{32}`, 3) + `"`,
		`ovh_consumerKey: "` + secrets.NewSecretWithEntropy(`[A-Za-z0-9-]{32}`, 3) + `"`,
		`OVH_CONSUMER_KEY="` + secrets.NewSecretWithEntropy(`[A-Za-z0-9-]{32}`, 3) + `"`,
	}
	fps := []string{
		`consumer_key = "placeholder-consumer-key"`,
		`OVH_CONSUMER_KEY="too-short"`,
	}

	return utils.Validate(r, tps, fps)
}

func OVHApplicationSecret() *config.Rule {
	r := config.Rule{
		RuleID:      "ovh-application-secret",
		Description: "OVHcloud Application Secret - component of authenticated OVH API requests, which could allow unauthorized access to OVHcloud infrastructure when combined with Application and Consumer keys.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"app(?:lication)?[_.-]{0,1}secret"}, `[A-Za-z0-9-]{32}`, true),
		Entropy:     3,
		Keywords:    []string{"ovh"},
		ValidateCEL: `cel.bind(ts, time.now_unix(),
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
		RequiredRules: []*config.Required{
			{
				RuleID:      "ovh-application-key",
				WithinLines: utils.Ptr(20),
			},
			{
				RuleID:      "ovh-consumer-key",
				WithinLines: utils.Ptr(20),
			},
		},
	}

	tps := []string{
		`ovh_application_secret = "` + secrets.NewSecretWithEntropy(`[A-Za-z0-9-]{32}`, 3) + `"`,
		`ovh_applicationSecret: "` + secrets.NewSecretWithEntropy(`[A-Za-z0-9-]{32}`, 3) + `"`,
		`OVH_APPLICATION_SECRET="` + secrets.NewSecretWithEntropy(`[A-Za-z0-9-]{32}`, 3) + `"`,
	}
	fps := []string{
		`ovh_application_secret = "placeholder-secret"`,
		`OVH_APPLICATION_SECRET="example-secret-value"`,
	}

	return utils.Validate(r, tps, fps)
}
