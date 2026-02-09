package scan

import (
	"github.com/betterleaks/betterleaks"
	"github.com/betterleaks/betterleaks/config"
)

func withinProximity(primary, required betterleaks.Finding, requiredRule *config.Required) bool {
	// If neither within_lines nor within_columns is set, findings just need to be in the same fragment
	if requiredRule.WithinLines == nil && requiredRule.WithinColumns == nil {
		return true
	}

	// Check line proximity (vertical distance)
	if requiredRule.WithinLines != nil {
		lineDiff := abs(primary.StartLine - required.StartLine)
		if lineDiff > *requiredRule.WithinLines {
			return false
		}
	}

	// Check column proximity (horizontal distance)
	if requiredRule.WithinColumns != nil {
		// Use the start column of each finding for proximity calculation
		colDiff := abs(primary.StartColumn - required.StartColumn)
		if colDiff > *requiredRule.WithinColumns {
			return false
		}
	}

	return true
}

// abs returns the absolute value of an integer
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
