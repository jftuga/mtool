package generate

import (
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"github.com/jftuga/mtool/internal/shared"
	"os"
)

// Config holds configuration for the generate command.
type Config struct {
	Mode    string
	Length  int
	Count   int
	Charset string
	Stdout  io.Writer
}

// Option configures a Config.
type Option func(*Config)

func WithMode(mode string) Option       { return func(c *Config) { c.Mode = mode } }
func WithLength(length int) Option      { return func(c *Config) { c.Length = length } }
func WithCount(count int) Option        { return func(c *Config) { c.Count = count } }
func WithCharset(charset string) Option { return func(c *Config) { c.Charset = charset } }
func WithStdout(w io.Writer) Option     { return func(c *Config) { c.Stdout = w } }

// Run generates passwords, tokens, or random data.
func Run(opts ...Option) error {
	cfg := &Config{Mode: "password", Length: 20, Count: 1, Charset: "full", Stdout: os.Stdout}
	for _, o := range opts {
		o(cfg)
	}

	for range cfg.Count {
		var result string
		var err error
		switch cfg.Mode {
		case "password":
			result, err = GeneratePassword(cfg.Length, cfg.Charset)
		case "token":
			result, err = GenerateToken(cfg.Length)
		case "bytes":
			err = GenerateRandomBytes(cfg.Length, cfg.Stdout)
		case "uuid":
			result, err = GenerateUUID()
		case "bigint":
			result, err = GenerateBigInt(cfg.Length)
		default:
			return fmt.Errorf("unknown mode: %s", cfg.Mode)
		}
		if err != nil {
			return err
		}
		if result != "" {
			fmt.Fprintln(cfg.Stdout, result)
		}
	}
	return nil
}

// GeneratePassword generates a cryptographically secure password.
func GeneratePassword(length int, charset string) (string, error) {
	var chars string
	switch charset {
	case "alpha":
		chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	case "alnum":
		chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	default:
		chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
	}

	result := make([]byte, length)
	for i := range length {
		idx, err := shared.CryptoRandIntn(len(chars))
		if err != nil {
			return "", fmt.Errorf("generating password: %w", err)
		}
		result[i] = chars[idx]
	}

	// Ensure at least one of each category for 'full' charset
	if charset == "full" && length >= 4 {
		categories := []string{
			"abcdefghijklmnopqrstuvwxyz",
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			"0123456789",
			"!@#$%^&*()-_=+[]{}|;:,.<>?",
		}
		for i, cat := range categories {
			if i < length {
				idx, err := shared.CryptoRandIntn(len(cat))
				if err != nil {
					return "", fmt.Errorf("generating password: %w", err)
				}
				result[i] = cat[idx]
			}
		}
		// Shuffle using crypto/rand
		for i := len(result) - 1; i > 0; i-- {
			j, err := shared.CryptoRandIntn(i + 1)
			if err != nil {
				return "", fmt.Errorf("shuffling password: %w", err)
			}
			result[i], result[j] = result[j], result[i]
		}
	}

	return string(result), nil
}

// GenerateToken generates a hex-encoded random token.
func GenerateToken(length int) (string, error) {
	b := make([]byte, (length+1)/2)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b)[:length], nil
}

// GenerateRandomBytes outputs raw random bytes to the writer.
func GenerateRandomBytes(length int, w io.Writer) error {
	b := make([]byte, length)
	if _, err := crand.Read(b); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

// GenerateUUID generates an RFC 4122 v4 UUID.
func GenerateUUID() (string, error) {
	var uuid [16]byte
	if _, err := crand.Read(uuid[:]); err != nil {
		return "", err
	}
	// Set version 4 and variant bits
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(uuid[0:4]),
		binary.BigEndian.Uint16(uuid[4:6]),
		binary.BigEndian.Uint16(uuid[6:8]),
		binary.BigEndian.Uint16(uuid[8:10]),
		uuid[10:16],
	), nil
}

// GenerateBigInt generates a random big integer with the specified bit length.
func GenerateBigInt(bits int) (string, error) {
	max := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	n, err := crand.Int(crand.Reader, max)
	if err != nil {
		return "", err
	}
	return n.String(), nil
}
