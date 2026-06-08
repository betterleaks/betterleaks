package sources

import (
	"io"
	"strings"
	"testing"
)

func TestListenForStdErrPreservesMessage(t *testing.T) {
	r := io.NopCloser(strings.NewReader("fatal: not a git repository\nanother problem\n"))
	errCh := make(chan error, 1)

	listenForStdErr(r, errCh)

	err := <-errCh
	if err == nil {
		t.Fatal("expected an error from non-empty git stderr")
	}
	for _, want := range []string{"fatal: not a git repository", "another problem"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should contain %q", err.Error(), want)
		}
	}
}

func TestListenForStdErrIgnoresBenignWarnings(t *testing.T) {
	const benign = "Auto packing the repository in background for optimum performance\n" +
		"exhaustive rename detection was skipped due to too many files\n"
	r := io.NopCloser(strings.NewReader(benign))
	errCh := make(chan error, 1)

	listenForStdErr(r, errCh)

	if err := <-errCh; err != nil {
		t.Fatalf("benign git warnings should not produce an error, got: %v", err)
	}
}
