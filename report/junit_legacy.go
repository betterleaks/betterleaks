package report

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"

	"github.com/betterleaks/betterleaks"
)

// --------------------------------------------------------------------------
// Legacy (gitleaks-compatible) JUnit reporter.
//
// LegacyJunitReporter outputs JUnit XML with the gitleaks test suite name
// and gitleaks-shaped JSON in failure data. Activated by --legacy.
// --------------------------------------------------------------------------

// LegacyJunitReporter writes findings in the gitleaks-compatible JUnit format.
type LegacyJunitReporter struct{}

var _ betterleaks.Reporter = (*LegacyJunitReporter)(nil)

func (r *LegacyJunitReporter) Write(w io.WriteCloser, findings []betterleaks.Finding) error {
	testSuites := TestSuites{
		TestSuites: legacyGetTestSuites(findings),
	}

	io.WriteString(w, xml.Header)
	encoder := xml.NewEncoder(w)
	encoder.Indent("", "\t")
	return encoder.Encode(testSuites)
}

func legacyGetTestSuites(findings []betterleaks.Finding) []TestSuite {
	return []TestSuite{
		{
			// Legacy: use "gitleaks" test suite name.
			Failures:  strconv.Itoa(len(findings)),
			Name:      "gitleaks",
			Tests:     strconv.Itoa(len(findings)),
			TestCases: legacyGetTestCases(findings),
			Time:      "",
		},
	}
}

func legacyGetTestCases(findings []betterleaks.Finding) []TestCase {
	testCases := []TestCase{}
	for _, f := range findings {
		testCase := TestCase{
			Classname: f.Description,
			Failure:   legacyGetFailure(f),
			File:      f.Metadata[betterleaks.MetaPath],
			Name:      legacyGetMessage(f),
			Time:      "",
		}
		testCases = append(testCases, testCase)
	}
	return testCases
}

func legacyGetFailure(f betterleaks.Finding) Failure {
	return Failure{
		Data:    legacyGetData(f),
		Message: legacyGetMessage(f),
		Type:    f.Description,
	}
}

func legacyGetData(f betterleaks.Finding) string {
	// Legacy: use LegacyMarshalJSON for failure data.
	data, err := f.LegacyMarshalJSON()
	if err != nil {
		fmt.Println(err)
		return ""
	}
	// Pretty-print with indentation to match original gitleaks output.
	var buf json.RawMessage = data
	pretty, err := json.MarshalIndent(buf, "", "\t")
	if err != nil {
		return string(data)
	}
	return string(pretty)
}

func legacyGetMessage(f betterleaks.Finding) string {
	commit := f.Metadata[betterleaks.MetaCommitSHA]
	file := f.Metadata[betterleaks.MetaPath]
	if commit == "" {
		return fmt.Sprintf("%s has detected a secret in file %s, line %s.", f.RuleID, file, strconv.Itoa(f.StartLine))
	}
	return fmt.Sprintf("%s has detected a secret in file %s, line %s, at commit %s.", f.RuleID, file, strconv.Itoa(f.StartLine), commit)
}
