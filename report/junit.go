package report

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"

	"github.com/betterleaks/betterleaks/sources"
)

type JunitReporter struct {
}

var _ Reporter = (*JunitReporter)(nil)
var _ StreamReporter = (*JunitReporter)(nil)

func (r *JunitReporter) Write(w io.Writer, findings []Finding) error {
	// Preserve the slice API's all-or-nothing behavior for marshal errors. The
	// streaming API receives already-spooled, JSON-safe findings from the CLI.
	for i := range findings {
		if _, err := getFailure(findings[i]); err != nil {
			return err
		}
	}
	return r.WriteStream(w, len(findings), iterateFindings(findings))
}

func (r *JunitReporter) WriteStream(w io.Writer, count int, findings FindingIterator) error {
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	encoder := xml.NewEncoder(w)
	encoder.Indent("", "\t")
	testSuites := xml.StartElement{Name: xml.Name{Local: "testsuites"}}
	if err := encoder.EncodeToken(testSuites); err != nil {
		return err
	}
	testSuite := xml.StartElement{
		Name: xml.Name{Local: "testsuite"},
		Attr: []xml.Attr{
			{Name: xml.Name{Local: "failures"}, Value: strconv.Itoa(count)},
			{Name: xml.Name{Local: "name"}, Value: "betterleaks"},
			{Name: xml.Name{Local: "tests"}, Value: strconv.Itoa(count)},
			{Name: xml.Name{Local: "time"}, Value: ""},
		},
	}
	if err := encoder.EncodeToken(testSuite); err != nil {
		return err
	}

	if err := findings(func(f Finding) error {
		failure, err := getFailure(f)
		if err != nil {
			return err
		}
		testCase := TestCase{
			Classname: f.Description,
			Failure:   failure,
			File:      f.Attr(sources.AttrPath),
			Name:      getMessage(f),
			Time:      "",
		}
		return encoder.Encode(testCase)
	}); err != nil {
		return err
	}

	if err := encoder.EncodeToken(testSuite.End()); err != nil {
		return err
	}
	if err := encoder.EncodeToken(testSuites.End()); err != nil {
		return err
	}
	return encoder.Flush()
}

func getFailure(f Finding) (Failure, error) {
	data, err := getData(f)
	if err != nil {
		return Failure{}, err
	}
	return Failure{
		Data:    data,
		Message: getMessage(f),
		Type:    f.Description,
	}, nil
}

func getData(f Finding) (string, error) {
	data, err := json.MarshalIndent(f, "", "\t")
	if err != nil {
		return "", fmt.Errorf("marshal finding for JUnit: %w", err)
	}
	return string(data), nil
}

func getMessage(f Finding) string {
	path := f.Attr(sources.AttrPath)
	commit := f.Attr(sources.AttrGitSHA)
	if commit == "" {
		return fmt.Sprintf("%s has detected a secret in file %s, line %s.", f.RuleID, path, strconv.Itoa(f.StartLine))
	}

	return fmt.Sprintf("%s has detected a secret in file %s, line %s, at commit %s.", f.RuleID, path, strconv.Itoa(f.StartLine), commit)
}

type TestSuites struct {
	XMLName    xml.Name    `xml:"testsuites"`
	TestSuites []TestSuite `xml:"testsuite"`
}

type TestSuite struct {
	XMLName   xml.Name   `xml:"testsuite"`
	Failures  string     `xml:"failures,attr"`
	Name      string     `xml:"name,attr"`
	Tests     string     `xml:"tests,attr"`
	TestCases []TestCase `xml:"testcase"`
	Time      string     `xml:"time,attr"`
}

type TestCase struct {
	XMLName   xml.Name `xml:"testcase"`
	Classname string   `xml:"classname,attr"`
	Failure   Failure  `xml:"failure"`
	File      string   `xml:"file,attr"`
	Name      string   `xml:"name,attr"`
	Time      string   `xml:"time,attr"`
}

type Failure struct {
	XMLName xml.Name `xml:"failure"`
	Data    string   `xml:",chardata"`
	Message string   `xml:"message,attr"`
	Type    string   `xml:"type,attr"`
}
