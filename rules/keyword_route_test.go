package rules

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/scan"
)

func TestAdafruitKeywordRoutesWhenRegexMatches(t *testing.T) {
	cfg := testConfig(t, "adafruit-api-key", "generic-api-key")
	// Broaden generic so both rules match the same adafruit assignment line.
	cfg.Rules[1].Regex = `(?i)(?:api_key|adafruit)[\s'"\x60]{0,3}[:=][\s'"\x60]{0,3}([\w.=-]{10,150})`
	const secret = "k7Qm2pLx9Vw4nR8sT1yU6zA3bC5dE0fH"
	assignment := "// api_key\nadafruit = \"" + secret + "\"\n"
	distant := "# 调用OpenAI的Embedding API生成文本的嵌入向量\n" +
		"embedding_model_handler_obj = embedding_model_handler('adafruit', 'embedding_model')\n" +
		"embedding_model = embedding_model_handler_obj(\n" +
		"    {'api_key': '" + secret + "'}\n" +
		")\n"
	for _, engine := range engines {
		t.Run(engine.Version(), func(t *testing.T) {
			scanner, err := scan.New(cfg, scan.WithRegexEngine(engine), scan.WithWorkers(1))
			require.NoError(t, err)

			matched := scanner.ScanString(assignment)
			var matchedIDs []string
			for _, f := range matched {
				if f.Match.Value == secret {
					matchedIDs = append(matchedIDs, f.RuleID)
				}
			}
			require.ElementsMatch(t, []string{"generic-api-key", "adafruit-api-key"}, matchedIDs)

			distantFindings := scanner.ScanString(distant)
			var distantIDs []string
			for _, f := range distantFindings {
				if f.Match.Value == secret {
					distantIDs = append(distantIDs, f.RuleID)
				}
			}
			require.Equal(t, []string{"generic-api-key"}, distantIDs)
		})
	}
}

func TestAdafruitDistantGenericStaysGeneric(t *testing.T) {
	cfg := testConfig(t, "adafruit-api-key", "generic-api-key")
	const secret = "4v8l67z---wfu0y1vd_3l1cmfzxoud8e"
	raw := "handler('adafruit')\napi_key = \"" + secret + "\"\n"
	scanner, err := scan.New(cfg, scan.WithWorkers(1))
	require.NoError(t, err)
	findings := scanner.ScanString(raw)
	var ruleIDs []string
	for _, f := range findings {
		if f.Match.Value == secret {
			ruleIDs = append(ruleIDs, f.RuleID)
		}
	}
	require.Equal(t, []string{"generic-api-key"}, ruleIDs)
}

func TestCoverallsKeywordWithoutRegexStaysGeneric(t *testing.T) {
	cfg := testConfig(t, "coveralls-personal-api-token", "generic-api-key")
	const secret = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4p5q6r7s8t"
	raw := "embedding_model_handler_obj = embedding_model_handler('coveralls', 'embedding_model')\n" +
		"embedding_model = embedding_model_handler_obj(\n" +
		"    {'api_key': '" + secret + "'}\n" +
		")\n"
	scanner, err := scan.New(cfg, scan.WithWorkers(1))
	require.NoError(t, err)
	var ruleIDs []string
	for _, f := range scanner.ScanString(raw) {
		if f.Match.Value == secret {
			ruleIDs = append(ruleIDs, f.RuleID)
		}
	}
	require.Equal(t, []string{"generic-api-key"}, ruleIDs)
}
