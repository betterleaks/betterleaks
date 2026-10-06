package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/betterleaks/betterleaks/v2/fingerprint"
	"golang.org/x/term"
)

const maxFingerprintBytes = 1024 * 1024

const fingerprintHMACKeyEnv = "BETTERLEAKS_FINGERPRINT_HMAC_KEY"

func fingerprintKey(explicit *string) ([]byte, error) {
	if explicit != nil {
		if *explicit == "" {
			return nil, errors.New("--hmac-key must not be empty")
		}
		return []byte(*explicit), nil
	}
	key, set := os.LookupEnv(fingerprintHMACKeyEnv)
	if !set {
		return nil, nil
	}
	if key == "" {
		return nil, fmt.Errorf("%s must not be empty when set", fingerprintHMACKeyEnv)
	}
	return []byte(key), nil
}

type FingerprintCmd struct {
	HMACKey *string `name:"hmac-key" placeholder:"KEY" help:"HMAC fingerprint key; overrides BETTERLEAKS_FINGERPRINT_HMAC_KEY."`
}

func (cmd *FingerprintCmd) Run(runtime *commandRuntime) error {
	key, err := fingerprintKey(cmd.HMACKey)
	if err != nil {
		return err
	}
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
	_, err = fmt.Fprintln(runtime.stdout, fingerprint.Format(fingerprint.SumWithKey(secret, key)))
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
