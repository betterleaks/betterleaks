package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func FirebaseCloudMessagingServerKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "firebase-cloud-messaging-server-key",
		Description: "Firebase Cloud Messaging legacy server key.",
		Regex: utils.GenerateSemiGenericRegex(
			[]string{`(?:firebase|fcm)(?:[_. -]*(?:server|api))?[_. -]*(?:key|token)`},
			`AAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{120,180}`,
			true,
		),
		Keywords: []string{"firebase", "fcm"},
		Filter:   utils.MinEntropy(4.0),
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("firebase", "AAAA"+secrets.NewSecret(`[A-Za-z0-9_-]{7}`)+":APA91b"+secrets.NewSecretWithEntropy(`[A-Za-z0-9_-]{120}`, 4.0)),
	}
	fps := []string{
		`FIREBASE_SERVER_KEY=AAAAshort`,
	}
	return utils.Validate(r, tps, fps)
}
