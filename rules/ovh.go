package rules

import "github.com/betterleaks/betterleaks/v2/config"

var _ = Add(config.Rule{
	ID:          "ovh-application-key",
	Confidence:  "medium",
	Description: "OVHcloud Application Key - component of authenticated OVH API requests.",
	Regex:       Assignment([]string{"app(?:lication)?[_.-]{0,1}key"}, `(?i)[A-Za-z0-9-]{16}`),
	Keywords:    []string{"ovh"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: `ovh_application_key = "eoStCxpP3EVXcbLq"`,
			Expect: []config.ExpectedFinding{
				{Secret: "eoStCxpP3EVXcbLq"},
			},
		},
		{
			Name:  "true positive 2",
			Mode:  "match",
			Input: `ovh_applicationKey: "eoStCxpP3EVXcbLq"`,
			Expect: []config.ExpectedFinding{
				{Secret: "eoStCxpP3EVXcbLq"},
			},
		},
		{
			Name:  "true positive 3",
			Mode:  "match",
			Input: `OVH_APPLICATION_KEY="eoStCxpP3EVXcbLq"`,
			Expect: []config.ExpectedFinding{
				{Secret: "eoStCxpP3EVXcbLq"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  `application_key = "short-key"`,
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 2",
			Mode:   "match",
			Input:  `OVH_APPLICATION_KEY="<your-ovh-application-key>"`,
			Expect: []config.ExpectedFinding{},
		},
	},
})

var _ = Add(config.Rule{
	ID:          "ovh-consumer-key",
	Confidence:  "medium",
	Description: "OVHcloud Consumer Key - component of authenticated OVH API requests.",
	Regex:       Assignment([]string{"consumer[_.-]{0,1}key"}, `(?i)[A-Za-z0-9-]{32}`),
	Keywords:    []string{"ovh"},
	SkipReport:  true,
	FilterExpr:  `entropy(finding["secret"]) <= 2.0`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Mode:  "match",
			Input: `ovh_consumer_key = "eoStCxpP3EVXcbLq-Jt4b8wsZpgsxTmN"`,
			Expect: []config.ExpectedFinding{
				{Secret: "eoStCxpP3EVXcbLq-Jt4b8wsZpgsxTmN"},
			},
		},
		{
			Name:  "true positive 2",
			Mode:  "match",
			Input: `ovh_consumerKey: "eoStCxpP3EVXcbLq-Jt4b8wsZpgsxTmN"`,
			Expect: []config.ExpectedFinding{
				{Secret: "eoStCxpP3EVXcbLq-Jt4b8wsZpgsxTmN"},
			},
		},
		{
			Name:  "true positive 3",
			Mode:  "match",
			Input: `OVH_CONSUMER_KEY="eoStCxpP3EVXcbLq-Jt4b8wsZpgsxTmN"`,
			Expect: []config.ExpectedFinding{
				{Secret: "eoStCxpP3EVXcbLq-Jt4b8wsZpgsxTmN"},
			},
		},
		{
			Name:   "false positive 1",
			Mode:   "match",
			Input:  `consumer_key = "placeholder-consumer-key"`,
			Expect: []config.ExpectedFinding{},
		},
		{
			Name:   "false positive 2",
			Mode:   "match",
			Input:  `OVH_CONSUMER_KEY="too-short"`,
			Expect: []config.ExpectedFinding{},
		},
	},
})

var _ = Add(config.Rule{
	ID:          "ovh-application-secret",
	Confidence:  "high",
	Description: "OVHcloud Application Secret - component of authenticated OVH API requests, which could allow unauthorized access to OVHcloud infrastructure when combined with Application and Consumer keys.",
	Regex:       Assignment([]string{"app(?:lication)?[_.-]{0,1}secret"}, `(?i)[A-Za-z0-9-]{32}`),
	Keywords:    []string{"ovh"},
	ValidateExpr: `let ts = time.nowUnix(); (let url = "https://api.us.ovhcloud.com/1.0/auth/details"; (let sig_payload = finding["secret"] + "+" + (components["ovh-consumer-key"]?.secret ?? "") + "+GET+" + url + "++" + ts; (let sig = "$1$" + hex.encode(crypto.sha1(bytes(sig_payload))); (let r = http.get(url, {
            "X-Ovh-Application": (components["ovh-application-key"]?.secret ?? ""),
            "X-Ovh-Consumer": (components["ovh-consumer-key"]?.secret ?? ""),
            "X-Ovh-Timestamp": ts,
            "X-Ovh-Signature": sig
          }); r.status == 200 ? {
            "result": "valid"
          } : r.status in [400, 401, 403] ? {
            "result": "invalid",
            "reason": "Unauthorized"
          } : validate.unknown(r)))))`,
	Components: []config.Component{
		{
			RuleID: "ovh-application-key",
			Within: "20L",
		},
		{
			RuleID: "ovh-consumer-key",
			Within: "20L",
		},
	},
	FilterExpr: `entropy(finding["secret"]) <= 3.0`,
	Tests: []config.RuleTest{
		{
			Name:  "true positive 1",
			Input: "ovh_application_secret = \"eoStCxpP3EVXcbLq-Jt4b8wsZpgsxTmN\"\novh_application_key = \"eoStCxpP3EVXcbLq\"\novh_consumer_key = \"eoStCxpP3EVXcbLq-Jt4b8wsZpgsxTmN\"",
			Expect: []config.ExpectedFinding{
				{Secret: "eoStCxpP3EVXcbLq-Jt4b8wsZpgsxTmN", ComponentSets: []map[string]string{{"ovh-application-key": "eoStCxpP3EVXcbLq", "ovh-consumer-key": "eoStCxpP3EVXcbLq-Jt4b8wsZpgsxTmN"}}},
			},
		},
		{
			Name:  "true positive 2",
			Input: "ovh_applicationSecret: \"eoStCxpP3EVXcbLq-Jt4b8wsZpgsxTmN\"\novh_application_key = \"eoStCxpP3EVXcbLq\"\novh_consumer_key = \"eoStCxpP3EVXcbLq-Jt4b8wsZpgsxTmN\"",
			Expect: []config.ExpectedFinding{
				{Secret: "eoStCxpP3EVXcbLq-Jt4b8wsZpgsxTmN", ComponentSets: []map[string]string{{"ovh-application-key": "eoStCxpP3EVXcbLq", "ovh-consumer-key": "eoStCxpP3EVXcbLq-Jt4b8wsZpgsxTmN"}}},
			},
		},
		{
			Name:  "true positive 3",
			Input: "OVH_APPLICATION_SECRET=\"eoStCxpP3EVXcbLq-Jt4b8wsZpgsxTmN\"\novh_application_key = \"eoStCxpP3EVXcbLq\"\novh_consumer_key = \"eoStCxpP3EVXcbLq-Jt4b8wsZpgsxTmN\"",
			Expect: []config.ExpectedFinding{
				{Secret: "eoStCxpP3EVXcbLq-Jt4b8wsZpgsxTmN", ComponentSets: []map[string]string{{"ovh-application-key": "eoStCxpP3EVXcbLq", "ovh-consumer-key": "eoStCxpP3EVXcbLq-Jt4b8wsZpgsxTmN"}}},
			},
		},
		NoMatch("false positive 1", `ovh_application_secret = "placeholder-secret"`),
		NoMatch("false positive 2", `OVH_APPLICATION_SECRET="example-secret-value"`),
	},
})
