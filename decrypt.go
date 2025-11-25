package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/tink-crypto/tink-go/v2/streamingaead"
)

func decrypt() error {
	// Read header line from STDIN
	reader := bufio.NewReader(os.Stdin)
	headerLine, err := reader.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("failed to read header (is it a valid jfcrypt file?): %w", err)
	}

	// Parse header JSON
	var header SealedHeader
	if err := json.Unmarshal(headerLine, &header); err != nil {
		return fmt.Errorf("failed to parse header (is it a valid jfcrypt file?): %w", err)
	}

	// Validate version compatibility
	if header.Version == "" {
		return fmt.Errorf("invalid jfcrypt file: missing version")
	}

	// Validate algorithm
	if header.Algorithm != "AES256-GCM-HKDF-1MB" {
		return fmt.Errorf("unsupported algorithm: %s", header.Algorithm)
	}

	// Validate KDF
	if header.KDF.Algorithm != "argon2id" {
		return fmt.Errorf("unsupported KDF: %s", header.KDF.Algorithm)
	}

	// Validate format (default to base64 for backwards compatibility)
	format := header.Format
	if format == "" {
		format = "base64"
	}
	if format != "binary" && format != "base64" {
		return fmt.Errorf("unsupported format: %s", format)
	}

	// Decode salt
	salt, err := base64.StdEncoding.DecodeString(header.KDF.Salt)
	if err != nil {
		return fmt.Errorf("invalid salt encoding: %w", err)
	}

	// Get passphrase
	passphrase, err := getPassphrase("Enter passphrase: ")
	if err != nil {
		return fmt.Errorf("failed to get passphrase: %w", err)
	}
	defer zeroBytes(passphrase)

	if len(passphrase) == 0 {
		return fmt.Errorf("passphrase cannot be empty")
	}

	// Derive key using stored parameters
	key := deriveKey(
		passphrase,
		salt,
		header.KDF.Time,
		header.KDF.Memory,
		header.KDF.Threads,
		header.KDF.KeyLen,
	)
	defer zeroBytes(key)

	// Create Tink keyset
	keysetHandle, err := createKeysetFromKey(key)
	if err != nil {
		return fmt.Errorf("failed to create keyset: %w", err)
	}

	// Get streaming AEAD primitive
	primitive, err := streamingaead.New(keysetHandle)
	if err != nil {
		return fmt.Errorf("failed to create streaming AEAD: %w", err)
	}

	// Create input reader based on format
	var inputReader io.Reader
	if format == "base64" {
		inputReader = base64.NewDecoder(base64.StdEncoding, newNewlineTrimmingReader(reader))
	} else {
		inputReader = reader
	}

	// Create decrypting reader
	decReader, err := primitive.NewDecryptingReader(inputReader, []byte{})
	if err != nil {
		return fmt.Errorf("failed to create decrypting reader: %w", err)
	}

	// Stream to STDOUT
	writer := bufio.NewWriterSize(os.Stdout, 1024*1024) // 1MB buffer
	if _, err := io.Copy(writer, decReader); err != nil {
		return fmt.Errorf("decryption failed (wrong passphrase or corrupted data?): %w", err)
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush output: %w", err)
	}

	return nil
}

// newlineTrimmingReader wraps a reader and strips trailing newlines
type newlineTrimmingReader struct {
	r io.Reader
}

func newNewlineTrimmingReader(r io.Reader) *newlineTrimmingReader {
	return &newlineTrimmingReader{r: r}
}

func (t *newlineTrimmingReader) Read(p []byte) (n int, err error) {
	n, err = t.r.Read(p)
	if n > 0 {
		// Trim trailing newlines from the chunk
		for n > 0 && (p[n-1] == '\n' || p[n-1] == '\r') {
			n--
		}
	}
	return n, err
}
