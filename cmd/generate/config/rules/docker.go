package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func DockerSwarmJoinToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "docker-swarm-join-token",
		Description: "Docker Swarm join token.",
		Regex:       regexp.MustCompile(`\b(SWMTKN-1-[a-z0-9]{50,60}-[a-z0-9]{24,30})`),
		Keywords:    []string{"SWMTKN-1-"},
		Filter:      utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"docker swarm join --token SWMTKN-1-" + secrets.NewSecretWithEntropy(`[a-z0-9]{50}`, 3.5) + "-" + secrets.NewSecretWithEntropy(`[a-z0-9]{24}`, 3.5),
	}
	fps := []string{
		`SWMTKN-1-short`,
	}
	return utils.Validate(r, tps, fps)
}

func DockerSwarmUnlockKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "docker-swarm-unlock-key",
		Description: "Docker Swarm unlock key.",
		Regex:       regexp.MustCompile(`\b(SWMKEY-1-[A-Za-z0-9+/]{40,50})`),
		Keywords:    []string{"SWMKEY-1-"},
		Filter:      utils.MinEntropy(3.5),
	}

	// validate
	tps := []string{
		"docker swarm unlock --key SWMKEY-1-" + secrets.NewSecretWithEntropy(`[A-Za-z0-9+/]{40}`, 3.5),
	}
	fps := []string{
		`SWMKEY-1-short`,
	}
	return utils.Validate(r, tps, fps)
}
