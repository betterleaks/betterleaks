package report

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
)

type JunitReporter struct {
}

var _ Reporter = (*JunitReporter)(nil)

func (r *JunitReporter) Write(w io.Writer, findings []Finding) error {
	suites, err := getTestSuites(findings)
	if err != nil {
		return err
	}
	testSuites := TestSuites{
		TestSuites: suites,
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	encoder := xml.NewEncoder(w)
	encoder.Indent("", "\t")
	return encoder.Encode(testSuites)
}

func getTestSuites(findings []Finding) ([]TestSuite, error) {
	testCases, err := getTestCases(findings)
	if err != nil {
		return nil, err
	}
	return []TestSuite{
		{
			Failures:  strconv.Itoa(len(findings)),
			Name:      "betterleaks",
			Tests:     strconv.Itoa(len(findings)),
			TestCases: testCases,
			Time:      "",
		},
	}, nil
}

func getTestCases(findings []Finding) ([]TestCase, error) {
	testCases := []TestCase{}
	for _, f := range findings {
		failure, err := getFailure(f)
		if err != nil {
			return nil, err
		}
		testCase := TestCase{
			Classname: f.Description,
			Failure:   failure,
			File:      f.File,
			Name:      getMessage(f),
			Time:      "",
		}
		testCases = append(testCases, testCase)
	}
	return testCases, nil
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
	if f.Commit == "" {
		return fmt.Sprintf("%s has detected a secret in file %s, line %s.", f.RuleID, f.File, strconv.Itoa(f.StartLine))
	}

	return fmt.Sprintf("%s has detected a secret in file %s, line %s, at commit %s.", f.RuleID, f.File, strconv.Itoa(f.StartLine), f.Commit)
}

type TestSuites struct {
	XMLName    xml.Name `xml:"testsuites"`
	TestSuites []TestSuite
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
