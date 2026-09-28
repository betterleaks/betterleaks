package scan

import "fmt"

// Filters are part of the configured detection policy. Reject invalid programs
// before scanning, even when their rules would never match the input.
func (s *Scanner) compileFilters(global string) error {
	if global != "" {
		program, err := s.exprRuntime.CompileFilter(global, nil)
		if err != nil {
			return fmt.Errorf("compiling global filter: %w", err)
		}
		s.globalFilter = program
	}
	for i := range s.rulesBySpecificity {
		rule := &s.rulesBySpecificity[i]
		if rule.rule.FilterExpr == "" {
			continue
		}
		program, err := s.exprRuntime.CompileFilter(rule.rule.FilterExpr, nil)
		if err != nil {
			return fmt.Errorf("compiling rule %s filter: %w", rule.rule.ID, err)
		}
		rule.filter = program
	}
	return nil
}
