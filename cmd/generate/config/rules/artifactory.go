package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func ArtifactoryApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "artifactory-api-key",
		Description: "Detected an Artifactory api key, posing a risk unauthorized access to the central repository.",
		Regex:       regexp.MustCompile(`\bAKCp[A-Za-z0-9]{68,70}\b`),
		Keywords:    []string{"AKCp"},
		RequiredRules: []*config.Required{
			{RuleID: "artifactory-jfrog-url"},
		},
		ValidateCEL: `cel.bind(r,
  http.get("https://" + captures["artifactory-jfrog-url"] + "/artifactory/api/repositories", {
    "X-JFrog-Art-Api": finding["secret"]
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: `filter.entropy(finding["secret"]) < 3.5`,
	}

	// validate
	tps := []string{
		"artifactoryApiKey := \"AKCp" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("69"), 4.5) + "\"",
	}
	// false positives
	fps := []string{
		`lowEntropy := AKCpXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,
		"wrongStart := \"AkCp" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("69"), 4.5) + "\"",
		"wrongLength := \"AkCp" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("59"), 4.5) + "\"",
		"partOfAlongUnrelatedBlob gYnkgAkCp" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("69"), 4.5) + "VyZSB2",
	}

	return utils.Validate(r, tps, fps)
}

func ArtifactoryReferenceToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "artifactory-reference-token",
		Description: "Detected an Artifactory reference token, posing a risk of impersonation and unauthorized access to the central repository.",
		Regex:       regexp.MustCompile(`\bcmVmd[A-Za-z0-9]{59}\b`),
		Keywords:    []string{"cmVmd"},
		RequiredRules: []*config.Required{
			{RuleID: "artifactory-jfrog-url"},
		},
		ValidateCEL: `cel.bind(r,
  http.get("https://" + captures["artifactory-jfrog-url"] + "/artifactory/api/repositories", {
    "Authorization": "Bearer " + finding["secret"]
  }),
  r.status == 200 ? {
    "result": "valid"
  } : r.status in [401, 403] ? {
    "result": "invalid",
    "reason": "Unauthorized"
  } : validate.unknown(r)
)`,
		Filter: `filter.entropy(finding["secret"]) < 3.5`,
	}

	// validate
	tps := []string{
		"artifactoryRefToken := \"cmVmd" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("59"), 4.5) + "\"",
	}
	// false positives
	fps := []string{
		`lowEntropy := cmVmdXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,
		"wrongStart := \"cmVMd" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("59"), 4.5) + "\"",
		"wrongLength := \"cmVmd" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("49"), 4.5) + "\"",
		"partOfAlongUnrelatedBlob gYnkgcmVmd" + secrets.NewSecretWithEntropy(utils.AlphaNumeric("59"), 4.5) + "VyZSB2",
	}

	return utils.Validate(r, tps, fps)
}

func ArtifactoryJFrogURL() *config.Rule {
	r := config.Rule{
		RuleID:      "artifactory-jfrog-url",
		Description: "Detected a JFrog Artifactory host, used as a component of Artifactory token validation.",
		Regex:       regexp.MustCompile(`(?i)(?:^|[^a-z0-9-])([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.jfrog\.io)(?:$|[^a-z0-9-])`),
		Keywords:    []string{"jfrog.io"},
		SkipReport:  true,
		Filter:      `filter.entropy(finding["secret"]) < 2.5`,
	}

	tps := []string{
		`ARTIFACTORY_URL=https://mycompany.jfrog.io`,
		`JFROG_URL=my-company-name.jfrog.io`,
		`host: a.jfrog.io`,
	}
	fps := []string{
		`JFROG_URL=-bad.jfrog.io`,
		`JFROG_URL=bad-.jfrog.io`,
	}
	return utils.Validate(r, tps, fps)
}
