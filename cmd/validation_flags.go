package cmd

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

func getValidationMaxRequests(cmd *cobra.Command) (int, error) {
	maxRequests, err := cmd.Flags().GetInt("validation-max-requests")
	if err != nil {
		return 0, err
	}
	if maxRequests < 0 {
		return 0, fmt.Errorf("must be non-negative")
	}
	return maxRequests, nil
}

func validateValidationRPS(rps float64) error {
	if math.IsNaN(rps) || math.IsInf(rps, 0) || rps < 0 {
		return fmt.Errorf("must be a finite non-negative number")
	}
	return nil
}

func parseValidationRuleRPS(values []string) (map[string]float64, error) {
	rates := make(map[string]float64, len(values))
	for _, value := range values {
		rawRuleID, rawRPS, ok := strings.Cut(value, "=")
		if !ok {
			return nil, fmt.Errorf("invalid value %q: expected RULE=RPS", value)
		}
		ruleID := strings.TrimSpace(rawRuleID)
		if ruleID == "" {
			return nil, fmt.Errorf("invalid value %q: rule ID cannot be empty", value)
		}
		if _, exists := rates[ruleID]; exists {
			return nil, fmt.Errorf("duplicate rate for rule %q", ruleID)
		}

		rps, err := strconv.ParseFloat(strings.TrimSpace(rawRPS), 64)
		if err != nil {
			return nil, fmt.Errorf("invalid rate for rule %q: %w", ruleID, err)
		}
		if err := validateValidationRPS(rps); err != nil || rps == 0 {
			if err == nil {
				err = fmt.Errorf("must be greater than zero")
			}
			return nil, fmt.Errorf("invalid rate for rule %q: %w", ruleID, err)
		}
		rates[ruleID] = rps
	}
	return rates, nil
}
