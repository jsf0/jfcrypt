package main

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/term"
)

// zeroBytes overwrites a byte slice with zeros
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func getPassphrase(prompt string) ([]byte, error) {
	// First check environment variable
	if envPass := os.Getenv(PassphraseEnvVar); envPass != "" {
		return []byte(envPass), nil
	}

	// Read from terminal
	passphrase, err := readPassword(prompt)
	if err != nil {
		return nil, err
	}

	return passphrase, nil
}

func getPassphraseWithConfirm(prompt, confirmPrompt string) ([]byte, error) {
	// First check environment variable
	if envPass := os.Getenv(PassphraseEnvVar); envPass != "" {
		return []byte(envPass), nil
	}

	// Read from terminal
	passphrase, err := readPassword(prompt)
	if err != nil {
		return nil, err
	}

	// Confirm
	confirm, err := readPassword(confirmPrompt)
	if err != nil {
		zeroBytes(passphrase)
		return nil, err
	}

	if !bytes.Equal(passphrase, confirm) {
		zeroBytes(passphrase)
		zeroBytes(confirm)
		return nil, fmt.Errorf("passphrases do not match")
	}

	zeroBytes(confirm)
	return passphrase, nil
}

func readPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)

	var passphrase []byte
	var err error

	if term.IsTerminal(int(syscall.Stdin)) {
		// STDIN is a terminal, use secure input
		passphrase, err = term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr) // Print newline after password input
	} else {
		// STDIN is not a terminal (piped), try to read from /dev/tty
		tty, ttyErr := os.Open("/dev/tty")
		if ttyErr != nil {
			// On Windows or when /dev/tty is not available
			if runtime.GOOS == "windows" {
				return nil, fmt.Errorf("passphrase must be set via %s environment variable when STDIN is piped", PassphraseEnvVar)
			}
			return nil, fmt.Errorf("cannot read passphrase: STDIN is piped and /dev/tty is not available. Set %s environment variable", PassphraseEnvVar)
		}
		defer tty.Close()

		fd := int(tty.Fd())
		passphrase, err = term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr) // Print newline after password input
	}

	if err != nil {
		return nil, err
	}

	return passphrase, nil
}
