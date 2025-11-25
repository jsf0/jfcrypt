package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/tink-crypto/tink-go/v2/streamingaead"
)

func encrypt(opts EncryptOptions) error {
	passphrase, err := getPassphraseWithConfirm("Enter passphrase: ", "Confirm passphrase: ")
	if err != nil {
		return fmt.Errorf("failed to get passphrase: %w", err)
	}
	defer zeroBytes(passphrase)

	if len(passphrase) == 0 {
		return fmt.Errorf("passphrase cannot be empty")
	}

	// Generate random salt
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key using Argon2id
	key := deriveKey(passphrase, salt, opts.Argon2Time, opts.Argon2Memory, Argon2Threads, Argon2KeyLen)
	defer zeroBytes(key)

	// Create Tink keyset for AES256-GCM-HKDF streaming
	keysetHandle, err := createKeysetFromKey(key)
	if err != nil {
		return fmt.Errorf("failed to create keyset: %w", err)
	}

	// Get streaming AEAD primitive
	primitive, err := streamingaead.New(keysetHandle)
	if err != nil {
		return fmt.Errorf("failed to create streaming AEAD: %w", err)
	}

	// Determine format string
	format := "binary"
	if opts.UseBase64 {
		format = "base64"
	}

	// Build and write header as first line
	header := SealedHeader{
		Version:   Version,
		Algorithm: "AES256-GCM-HKDF-1MB",
		Format:    format,
		KDF: KDFParams{
			Algorithm: "argon2id",
			Salt:      base64.StdEncoding.EncodeToString(salt),
			Time:      opts.Argon2Time,
			Memory:    opts.Argon2Memory,
			Threads:   Argon2Threads,
			KeyLen:    Argon2KeyLen,
		},
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("failed to marshal header: %w", err)
	}

	// Write header line
	if _, err := os.Stdout.Write(headerBytes); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if _, err := os.Stdout.Write([]byte("\n")); err != nil {
		return fmt.Errorf("failed to write header newline: %w", err)
	}

	// Create buffered stdout writer
	stdoutBuf := bufio.NewWriterSize(os.Stdout, 1024*1024)

	var outputWriter io.WriteCloser

	if opts.UseBase64 {
		// Create base64 encoder that writes to stdout
		outputWriter = base64.NewEncoder(base64.StdEncoding, stdoutBuf)
	} else {
		// Write directly to stdout buffer
		outputWriter = &nopCloser{stdoutBuf}
	}

	// Create encrypting writer with empty associated data
	encWriter, err := primitive.NewEncryptingWriter(outputWriter, []byte{})
	if err != nil {
		return fmt.Errorf("failed to create encrypting writer: %w", err)
	}

	// Stream from STDIN directly to encrypted output
	reader := bufio.NewReaderSize(os.Stdin, 1024*1024) // 1MB buffer
	if _, err := io.Copy(encWriter, reader); err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	if err := encWriter.Close(); err != nil {
		return fmt.Errorf("failed to finalize encryption: %w", err)
	}

	if err := outputWriter.Close(); err != nil {
		return fmt.Errorf("failed to finalize output: %w", err)
	}

	// Write final newline for base64 format
	if opts.UseBase64 {
		if _, err := stdoutBuf.Write([]byte("\n")); err != nil {
			return fmt.Errorf("failed to write final newline: %w", err)
		}
	}

	if err := stdoutBuf.Flush(); err != nil {
		return fmt.Errorf("failed to flush output: %w", err)
	}

	return nil
}

// nopCloser wraps a Writer to provide a no-op Close method
type nopCloser struct {
	io.Writer
}

func (n *nopCloser) Close() error {
	return nil
}
