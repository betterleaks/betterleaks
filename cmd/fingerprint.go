package cmd

import (
	"errors"
	"fmt"
	"io"

	"github.com/betterleaks/betterleaks/internal/fingerprint"
	"golang.org/x/term"
)

const maxFingerprintBytes = 1024 * 1024

type FingerprintCmd struct{}

func (cmd *FingerprintCmd) Run(runtime *commandRuntime) error {
	secret, err := readFingerprintInput(runtime.stdin, runtime.stderr, term.IsTerminal, term.ReadPassword)
	if err != nil {
		return err
	}
	if len(secret) == 0 {
		return errors.New("secret must not be empty")
	}
	if len(secret) > maxFingerprintBytes {
		return fmt.Errorf("secret exceeds maximum size of %d bytes", maxFingerprintBytes)
	}
	_, err = fmt.Fprintln(runtime.stdout, fingerprint.Format(fingerprint.Sum(secret)))
	return err
}

func readFingerprintInput(in io.Reader, stderr io.Writer, isTerminal func(int) bool, readPassword func(int) ([]byte, error)) ([]byte, error) {
	if file, ok := in.(interface{ Fd() uintptr }); ok && isTerminal(int(file.Fd())) {
		_, _ = fmt.Fprint(stderr, "Secret: ")
		secret, err := readPassword(int(file.Fd()))
		_, _ = fmt.Fprintln(stderr)
		return secret, err
	}
	return io.ReadAll(io.LimitReader(in, maxFingerprintBytes+1))
}
