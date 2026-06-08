package report

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCSVFormulaInjectionSanitized(t *testing.T) {
	findings := []Finding{
		{
			RuleID:    "test-rule",
			Secret:    "=2+5+cmd|'/c calc'!A1",
			Match:     "@SUM(1+9)",
			File:      "-rm -rf /",
			Commit:    "+1",
			StartLine: 1,
		},
	}

	tmpfile, err := os.Create(filepath.Join(t.TempDir(), "inj.csv"))
	require.NoError(t, err)
	defer tmpfile.Close()
	require.NoError(t, (&CsvReporter{}).Write(tmpfile, findings))

	f, err := os.Open(tmpfile.Name())
	require.NoError(t, err)
	defer f.Close()
	records, err := csv.NewReader(f).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 2) // header + one finding

	row := records[1]
	for _, cell := range row {
		if cell != "" && strings.IndexByte(csvFormulaPrefixes, cell[0]) != -1 {
			t.Fatalf("unsanitized formula-trigger cell in CSV output: %q", cell)
		}
	}

	// The original (dangerous) values must survive, only neutralized with a
	// leading single quote — no data is lost.
	joined := strings.Join(row, "\x00")
	for _, want := range []string{"'=2+5+cmd|'/c calc'!A1", "'@SUM(1+9)", "'-rm -rf /", "'+1"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected sanitized value %q in row %v", want, row)
		}
	}
}
