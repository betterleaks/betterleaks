// == WARNING ==
// These functions are used to generate GitLeak's default config.
// You are free to use these in your own project, HOWEVER, no API stability is guaranteed.

package utils

import (
	"context"
	"strings"

	"github.com/betterleaks/betterleaks/cmd/generate/config/base"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources"
)

func Validate(rule config.Rule, truePositives []string, falsePositives []string) *config.Rule {
	r := &rule
	d := createSingleRuleDetector(r)
	for _, tp := range truePositives {
		count, err := countFindings(d, sources.Fragment{Raw: tp})
		if err != nil {
			logging.Fatal().Err(err).Str("rule", r.RuleID).Msg("Failed to validate true positive.")
		}
		if count < 1 {
			logging.Fatal().
				Str("rule", r.RuleID).
				Str("value", tp).
				Str("regex", r.Regex.String()).
				Msg("Failed to Validate. True positive was not detected by regex.")
		}
	}
	for _, fp := range falsePositives {
		count, err := countFindings(d, sources.Fragment{Raw: fp})
		if err != nil {
			logging.Fatal().Err(err).Str("rule", r.RuleID).Msg("Failed to validate false positive.")
		}
		if count != 0 {
			logging.Fatal().
				Str("rule", r.RuleID).
				Str("value", fp).
				Str("regex", r.Regex.String()).
				Msg("Failed to Validate. False positive was detected by regex.")
		}
	}
	return r
}

func ValidateWithPaths(rule config.Rule, truePositives map[string]string, falsePositives map[string]string) *config.Rule {
	r := &rule
	d := createSingleRuleDetector(r)
	for path, tp := range truePositives {
		f := sources.Fragment{
			Raw: tp,
			Attributes: map[string]string{
				sources.AttrPath: path,
			},
		}
		count, err := countFindings(d, f)
		if err != nil {
			logging.Fatal().Err(err).Str("rule", r.RuleID).Msg("Failed to validate true positive.")
		}
		if count != 1 {
			logging.Fatal().
				Str("rule", r.RuleID).
				Str("value", tp).
				Str("regex", r.Regex.String()).
				Str("path", r.Path.String()).
				Msg("Failed to Validate. True positive was not detected by regex and/or path.")
		}
	}
	for path, fp := range falsePositives {
		f := sources.Fragment{
			Raw: fp,
			Attributes: map[string]string{
				sources.AttrPath: path,
			},
		}
		count, err := countFindings(d, f)
		if err != nil {
			logging.Fatal().Err(err).Str("rule", r.RuleID).Msg("Failed to validate false positive.")
		}
		if count != 0 {
			logging.Fatal().
				Str("rule", r.RuleID).
				Str("value", fp).
				Str("regex", r.Regex.String()).
				Str("path", r.Path.String()).
				Msg("Failed to Validate. False positive was detected by regex and/or path.")
		}
	}
	return r
}

func createSingleRuleDetector(r *config.Rule) *detect.Detector {
	// normalize keywords like in the config package
	var (
		uniqueKeywords = make(map[string]struct{})
		keywords       []string
	)
	for _, keyword := range r.Keywords {
		k := strings.ToLower(keyword)
		if _, ok := uniqueKeywords[k]; ok {
			continue
		}
		keywords = append(keywords, k)
		uniqueKeywords[k] = struct{}{}
	}
	r.Keywords = keywords

	// SkipReport and Components are runtime concerns; strip them so the
	// generation-time regex validation can detect findings normally.
	testRule := *r
	testRule.SkipReport = false
	testRule.Components = nil
	rules := map[string]config.Rule{
		r.RuleID: testRule,
	}
	cfg := base.CreateGlobalConfig()
	cfg.Rules = rules
	cfg.Keywords = uniqueKeywords

	cfg.KeywordToRules = make(map[string][]string)
	if len(r.Keywords) == 0 {
		cfg.NoKeywordRules = []string{r.RuleID}
	} else {
		for _, k := range r.Keywords {
			cfg.KeywordToRules[k] = append(cfg.KeywordToRules[k], r.RuleID)
		}
	}

	return detect.NewDetectorContext(context.Background(), cfg, detect.ValidationOptions{})
}

func countFindings(d *detect.Detector, fragment sources.Fragment) (int, error) {
	count := 0
	for result := range d.Run(context.Background(), fragmentSource{fragment: fragment}) {
		if result.Err != nil {
			return 0, result.Err
		}
		count++
	}
	return count, nil
}

type fragmentSource struct {
	fragment sources.Fragment
}

func (s fragmentSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return yield(s.fragment, nil)
}
