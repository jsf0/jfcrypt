package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	Version = "1.0.0"

	// Environment variable for passphrase
	PassphraseEnvVar = "JFCRYPT_PASSPHRASE"
)

// EncryptOptions holds encryption parameters
type EncryptOptions struct {
	UseBase64    bool
	Argon2Memory uint32 // in KB
	Argon2Time   uint32
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		printUsage()
		return fmt.Errorf("no command specified")
	}

	command := os.Args[1]

	// Parse flags
	opts := EncryptOptions{
		UseBase64:    false,
		Argon2Memory: 1024 * 1024, // 1024 MB default
		Argon2Time:   3,         // 3 iterations default
	}

	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]

		if arg == "--base64" || arg == "-b" {
			opts.UseBase64 = true
		} else if strings.HasPrefix(arg, "--memory=") {
			val, err := parseMemory(strings.TrimPrefix(arg, "--memory="))
			if err != nil {
				return fmt.Errorf("invalid memory value: %w", err)
			}
			opts.Argon2Memory = val
		} else if strings.HasPrefix(arg, "-m=") {
			val, err := parseMemory(strings.TrimPrefix(arg, "-m="))
			if err != nil {
				return fmt.Errorf("invalid memory value: %w", err)
			}
			opts.Argon2Memory = val
		} else if strings.HasPrefix(arg, "--iterations=") {
			val, err := strconv.ParseUint(strings.TrimPrefix(arg, "--iterations="), 10, 32)
			if err != nil {
				return fmt.Errorf("invalid iterations value: %w", err)
			}
			if val < 1 {
				return fmt.Errorf("iterations must be at least 1")
			}
			opts.Argon2Time = uint32(val)
		} else if strings.HasPrefix(arg, "-i=") {
			val, err := strconv.ParseUint(strings.TrimPrefix(arg, "-i="), 10, 32)
			if err != nil {
				return fmt.Errorf("invalid iterations value: %w", err)
			}
			if val < 1 {
				return fmt.Errorf("iterations must be at least 1")
			}
			opts.Argon2Time = uint32(val)
		}
	}

	switch command {
	case "--encrypt", "-e":
		return encrypt(opts)
	case "--decrypt", "-d":
		return decrypt()
	case "--help", "-h":
		printUsage()
		return nil
	case "--version", "-v":
		fmt.Fprintf(os.Stderr, "jfcrypt version %s\n", Version)
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown command: %s", command)
	}
}

// parseMemory parses memory strings like "64", "64M", "64MB", "1G", "1GB"
// Bare numbers are treated as MB
func parseMemory(s string) (uint32, error) {
	s = strings.ToUpper(strings.TrimSpace(s))

	multiplier := uint64(1024) // default MB to KB

	if strings.HasSuffix(s, "GB") || strings.HasSuffix(s, "G") {
		multiplier = 1024 * 1024 // GB to KB
		s = strings.TrimSuffix(strings.TrimSuffix(s, "GB"), "G")
	} else if strings.HasSuffix(s, "MB") || strings.HasSuffix(s, "M") {
		multiplier = 1024 // MB to KB
		s = strings.TrimSuffix(strings.TrimSuffix(s, "MB"), "M")
	} else if strings.HasSuffix(s, "KB") || strings.HasSuffix(s, "K") {
		multiplier = 1
		s = strings.TrimSuffix(strings.TrimSuffix(s, "KB"), "K")
	}
	// else: bare number defaults to MB (multiplier = 1024)

	val, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}

	result := val * multiplier
	if result > 0xFFFFFFFF {
		return 0, fmt.Errorf("memory value too large")
	}

	if result < 1024 {
		return 0, fmt.Errorf("memory must be at least 1MB")
	}

	return uint32(result), nil
}

func printUsage() {
	usage := `jfcrypt - Streaming authenticated encryption for large files

USAGE:
    jfcrypt <command> [options]

COMMANDS:
    --encrypt, -e    Encrypt data from STDIN to STDOUT
    --decrypt, -d    Decrypt data from STDIN to STDOUT
    --help, -h          Show this help message
    --version, -v       Show version information

OPTIONS:
    --base64, -b            Use base64 encoding (text-safe but 33% larger)
    --memory=SIZE, -m=SIZE  Argon2 memory cost (default: 1G)
                            Accepts: 64M, 256M, 1G, etc.
    --iterations=N, -i=N    Argon2 iterations (default: 3)

PASSPHRASE:
    Set JFCRYPT_PASSPHRASE environment variable, or enter interactively.

EXAMPLES:
    # Encrypt with defaults (1GB memory, 3 iterations)
    cat backup.tar | jfcrypt encrypt > backup.tar.sealed

    # Encrypt with higher security (2GB memory)
    cat backup.tar | jfcrypt encrypt -m=2G > backup.tar.sealed

    # Encrypt with maximum paranoia (4GB memory, 4 iterations)
    cat backup.tar | jfcrypt encrypt -m=4G -i=4 > backup.tar.sealed

    # Decrypt (auto-detects parameters from header)
    cat backup.tar.sealed | jfcrypt decrypt > backup.tar

SECURITY:
    - Uses AES-256-GCM with 1MB segments (Tink Streaming AEAD)
    - Key derived using Argon2id
    - Each segment is independently authenticated
    - Safe for files of any size (streams with constant memory)

`
	fmt.Fprint(os.Stderr, usage)
}
