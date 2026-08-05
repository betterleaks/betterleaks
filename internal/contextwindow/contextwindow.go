// Package contextwindow parses directional line and character window specifications.
package contextwindow

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Mode determines how a context window is interpreted.
type Mode int

const (
	ModeNone Mode = iota
	ModeCols
	ModeBox
)

// Spec describes directional context boundaries around a match.
type Spec struct {
	Mode        Mode
	ColsBefore  int
	ColsAfter   int
	LinesBefore int
	LinesAfter  int
}

// IsZero reports whether no window is configured.
func (s Spec) IsZero() bool {
	return s.Mode == ModeNone
}

type direction struct {
	before     int
	after      int
	bidirected int
}

var tokenRE = regexp.MustCompile(`(?i)^([+-]?)(\d+)([CL]?)$`)

// Parse parses the grammar shared by --match-context and component within fields.
func Parse(value string) (Spec, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "0" {
		return Spec{}, nil
	}

	var cols, lines direction
	hasLines, hasCols := false, false

	for token := range strings.SplitSeq(value, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			return Spec{}, fmt.Errorf("empty token in context window %q", value)
		}

		matches := tokenRE.FindStringSubmatch(token)
		if matches == nil {
			return Spec{}, fmt.Errorf("invalid context window token %q", token)
		}

		directionMarker := matches[1]
		amount, _ := strconv.Atoi(matches[2])
		unit := strings.ToUpper(matches[3])
		if unit == "" {
			unit = "C"
		}

		if unit == "L" {
			hasLines = true
			amount = max(amount-1, 0)
			applyDirection(&lines, directionMarker, amount)
		} else {
			hasCols = true
			applyDirection(&cols, directionMarker, amount)
		}
	}

	spec := Spec{
		ColsBefore: max(cols.before, cols.bidirected),
		ColsAfter:  max(cols.after, cols.bidirected),
	}
	if hasLines {
		spec.Mode = ModeBox
		spec.LinesBefore = max(lines.before, lines.bidirected)
		spec.LinesAfter = max(lines.after, lines.bidirected)
	} else if hasCols {
		spec.Mode = ModeCols
	} else {
		return Spec{}, fmt.Errorf("invalid context window %q", value)
	}

	return spec, nil
}

func applyDirection(target *direction, marker string, amount int) {
	switch marker {
	case "-":
		target.before = max(target.before, amount)
	case "+":
		target.after = max(target.after, amount)
	default:
		target.bidirected = max(target.bidirected, amount)
	}
}
