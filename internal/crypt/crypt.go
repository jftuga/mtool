package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	crand "crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"mtool/internal/shared"
	"os"
)

const (
	Pbkdf2Iterations = 600_000
	SaltSize         = 16
)

// Config holds configuration for encrypt/decrypt commands.
type Config struct {
	Password   string
	InputPath  string
	OutputPath string
}

// Option configures a Config.
type Option func(*Config)

func WithPassword(password string) Option  { return func(c *Config) { c.Password = password } }
func WithInputPath(path string) Option     { return func(c *Config) { c.InputPath = path } }
func WithOutputPath(path string) Option    { return func(c *Config) { c.OutputPath = path } }

// RunEncrypt encrypts a file with AES-256-GCM.
func RunEncrypt(opts ...Option) error {
	cfg := &Config{}
	for _, o := range opts {
		o(cfg)
	}

	if cfg.InputPath == "" || cfg.OutputPath == "" {
		return errors.New("usage: mtool encrypt -password <pass> <input> <output>")
	}

	pass := ResolvePassword(cfg.Password)
	if pass == "" {
		return errors.New("password required: use -password flag or MTOOL_PASSWORD env var")
	}

	plaintext, err := os.ReadFile(cfg.InputPath)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	salt := make([]byte, SaltSize)
	if _, err := crand.Read(salt); err != nil {
		return fmt.Errorf("generating salt: %w", err)
	}

	key, err := DeriveKey([]byte(pass), salt)
	if err != nil {
		return fmt.Errorf("deriving key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := crand.Read(nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Output format: salt || nonce || ciphertext
	var out bytes.Buffer
	out.Write(salt)
	out.Write(nonce)
	out.Write(ciphertext)

	if err := os.WriteFile(cfg.OutputPath, out.Bytes(), 0o600); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	slog.Info("encrypted",
		"input", cfg.InputPath,
		"output", cfg.OutputPath,
		"size", shared.FormatSize(int64(out.Len())),
		"algorithm", "AES-256-GCM",
		"kdf", fmt.Sprintf("PBKDF2-SHA256 (%d iterations)", Pbkdf2Iterations),
	)
	return nil
}

// RunDecrypt decrypts a file encrypted with RunEncrypt.
func RunDecrypt(opts ...Option) error {
	cfg := &Config{}
	for _, o := range opts {
		o(cfg)
	}

	if cfg.InputPath == "" || cfg.OutputPath == "" {
		return errors.New("usage: mtool decrypt -password <pass> <input> <output>")
	}

	pass := ResolvePassword(cfg.Password)
	if pass == "" {
		return errors.New("password required: use -password flag or MTOOL_PASSWORD env var")
	}

	data, err := os.ReadFile(cfg.InputPath)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	if len(data) < SaltSize {
		return errors.New("input too short to contain encrypted data")
	}

	salt := data[:SaltSize]
	data = data[SaltSize:]

	key, err := DeriveKey([]byte(pass), salt)
	if err != nil {
		return fmt.Errorf("deriving key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return errors.New("input too short to contain nonce")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decryption failed (wrong password or corrupted data): %w", err)
	}

	if err := os.WriteFile(cfg.OutputPath, plaintext, 0o600); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	slog.Info("decrypted",
		"input", cfg.InputPath,
		"output", cfg.OutputPath,
		"size", shared.FormatSize(int64(len(plaintext))),
	)
	return nil
}

// ResolvePassword resolves a password from the flag value or environment variable.
func ResolvePassword(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv("MTOOL_PASSWORD")
}

// DeriveKey derives a 32-byte key using PBKDF2-SHA256.
func DeriveKey(password, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, string(password), salt, Pbkdf2Iterations, 32)
}
