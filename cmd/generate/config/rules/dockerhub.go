package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

const dockerHubTokenValidationExpr = `let user = lower(captures["dockerhub-username"]);
  let r = http.post("https://hub.docker.com/v2/auth/token", {
    "Accept": "application/json",
    "Content-Type": "application/json"
  }, "{\"identifier\":" + json.string(user) + ",\"secret\":" + json.string(finding["secret"]) + "}");
  r.status == 200 && (r.json?.access_token ?? "") != "" ? {
    "result": "valid",
    "profile": "https://hub.docker.com/u/" + user
  } : r.status == 401 ? {
    "result": "invalid",
    "reason": (r.json?.message ?? "Unauthorized")
  } : validate.unknown(r)`

func DockerHubPersonalAccessToken() *config.Rule {
	r := config.Rule{
		RuleID:      "dockerhub-personal-access-token",
		Description: "Detected a Docker Hub personal access token, which may expose Docker Hub account access.",
		Regex:       utils.GenerateUniqueTokenRegex(`dckr_pat_[A-Za-z0-9_-]{27}`, false),
		Keywords:    []string{"dckr_pat_"},
		RequiredRules: []*config.Required{
			{RuleID: "dockerhub-username", WithinLines: utils.Ptr(5)},
		},
		ValidateExpr: dockerHubTokenValidationExpr,
		Filter:       utils.MinEntropy(3.5),
	}

	tps := []string{
		`docker login -u gemesa -p dckr_pat_hc8VxYclixyTr2rDFsa2rqzkP3Y`,
		`docker login -u gemesa -p dckr_pat_tkzBYxjNNC3R_Yg6jd_O-G8FbrJ`,
	}
	return utils.Validate(r, tps, nil)
}

func DockerHubOrganizationAccessToken() *config.Rule {
	r := config.Rule{
		RuleID:      "dockerhub-organization-access-token",
		Description: "Detected a Docker Hub organization access token, which may expose organization repositories.",
		Regex:       utils.GenerateUniqueTokenRegex(`dckr_oat_[A-Za-z0-9_-]{32}`, false),
		Keywords:    []string{"dckr_oat_"},
		RequiredRules: []*config.Required{
			{RuleID: "dockerhub-username", WithinLines: utils.Ptr(5)},
		},
		ValidateExpr: dockerHubTokenValidationExpr,
		Filter:       utils.MinEntropy(3.5),
	}

	tps := []string{
		`docker login -u docker-test -p dckr_oat_7bA9zRt5-JqX3vP0l_MnY8sK2wE-dF6h`,
	}
	return utils.Validate(r, tps, nil)
}

// dockerHubIdentifier matches either an email address or a Docker ID (4-30 alphanumerics).
// Email is first so it wins the alternation instead of being truncated to its local part.
const dockerHubIdentifier = `[\w+-](?:[\w.+-]{0,62}[\w+-])?@[\w.-]+\.[a-z]{2,20}|[a-z0-9]{4,30}`

func DockerHubUsername() *config.Rule {
	r := config.Rule{
		RuleID:      "dockerhub-username",
		Description: "Detected a Docker Hub account identifier, used as a component of the Docker Hub access-token composite rules.",
		Regex: regexp.MustCompile(
			`(?i)(?:(?:[^a-z]|\A)(?:user(?:name)?|usr|-u|id|e-?mail)\S{0,40}?[:=\s]{1,3}[ '"=]?(` +
				dockerHubIdentifier + `)(?:[^a-z0-9@._+-]|\z)|(` + dockerHubIdentifier + `):dckr_(?:pat|oat)_)`),
		Keywords:   []string{"user", "usr", "-u", "id", "email", "dckr_pat_", "dckr_oat_"},
		SkipReport: true,
		Filter: "matchesAny(finding[\"secret\"], [`^(?i)(?:my|your|our|some|the)?" +
			"(?:user(?:name)?|org(?:anization)?|account|namespace|repo(?:sitory)?|image|project|team|" +
			"company|dockerid|dockeruser|example|test|demo|sample|placeholder|changeme|acme)\\d{0,4}$`])",
	}

	tps := []string{
		`docker login -u gemesa -p dckr_pat_hc8VxYclixyTr2rDFsa2rqzkP3Y`,
		`DOCKERHUB_USERNAME=alice42`,
		`username: buildbot42`,
		`alice42:dckr_pat_hc8VxYclixyTr2rDFsa2rqzkP3Y`,
		`DOCKER_EMAIL=bob@example.com`,
		`bob@example.com:dckr_oat_7bA9zRt5-JqX3vP0l_MnY8sK2wE-dF6h`,
	}
	fps := []string{
		`USERNAME=abc`,
		`provider = terraformcloud`,
		`DOCKERHUB_USERNAME=changeme`,
	}
	return utils.Validate(r, tps, fps)
}
