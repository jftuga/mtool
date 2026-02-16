package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Config holds configuration for the JWT decoder.
type Config struct {
	Raw    bool
	Token  string
	Stdout io.Writer
}

// Option configures a Config.
type Option func(*Config)

// WithRaw sets raw (compact JSON) output mode.
func WithRaw(raw bool) Option { return func(c *Config) { c.Raw = raw } }

// WithToken sets the JWT token string.
func WithToken(token string) Option { return func(c *Config) { c.Token = token } }

// WithStdout sets the output writer.
func WithStdout(w io.Writer) Option { return func(c *Config) { c.Stdout = w } }

// Run decodes and displays a JWT token.
func Run(opts ...Option) error {
	cfg := &Config{Stdout: os.Stdout}
	for _, o := range opts {
		o(cfg)
	}

	if cfg.Token == "" {
		return errors.New("usage: mtool jwt [options] <token>")
	}

	header, payload, err := DecodeJWT(cfg.Token)
	if err != nil {
		return err
	}

	var hdrJSON, plJSON []byte
	if cfg.Raw {
		hdrJSON, err = json.Marshal(header)
		if err != nil {
			return fmt.Errorf("marshaling header: %w", err)
		}
		plJSON, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshaling payload: %w", err)
		}
		fmt.Fprintf(cfg.Stdout, "%s\n%s\n", hdrJSON, plJSON)
	} else {
		hdrJSON, err = json.MarshalIndent(header, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling header: %w", err)
		}
		plJSON, err = json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling payload: %w", err)
		}
		fmt.Fprintf(cfg.Stdout, "Header:\n%s\n\nPayload:\n%s\n", hdrJSON, plJSON)
		expiry := FormatJWTExpiry(payload)
		if expiry != "" {
			fmt.Fprintf(cfg.Stdout, "\n%s\n", expiry)
		}
	}
	return nil
}

// DecodeJWT decodes a JWT token into header and payload maps.
func DecodeJWT(token string) (header, payload map[string]interface{}, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("decoding JWT header: %w", err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("decoding JWT payload: %w", err)
	}

	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, fmt.Errorf("parsing JWT header: %w", err)
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, fmt.Errorf("parsing JWT payload: %w", err)
	}
	return header, payload, nil
}

// FormatJWTExpiry formats JWT time claims (iat, nbf, exp).
func FormatJWTExpiry(payload map[string]interface{}) string {
	var sb strings.Builder

	if iat, ok := payload["iat"]; ok {
		if f, ok := iat.(float64); ok {
			t := time.Unix(int64(f), 0)
			fmt.Fprintf(&sb, "Issued At:  %s\n", t.UTC().Format(time.RFC3339))
		}
	}
	if nbf, ok := payload["nbf"]; ok {
		if f, ok := nbf.(float64); ok {
			t := time.Unix(int64(f), 0)
			fmt.Fprintf(&sb, "Not Before: %s\n", t.UTC().Format(time.RFC3339))
		}
	}
	if exp, ok := payload["exp"]; ok {
		if f, ok := exp.(float64); ok {
			t := time.Unix(int64(f), 0)
			now := time.Now()
			if now.After(t) {
				fmt.Fprintf(&sb, "Expires:    %s (EXPIRED %s ago)\n", t.UTC().Format(time.RFC3339), now.Sub(t).Round(time.Second))
			} else {
				fmt.Fprintf(&sb, "Expires:    %s (valid for %s)\n", t.UTC().Format(time.RFC3339), t.Sub(now).Round(time.Second))
			}
		}
	}
	return strings.TrimRight(sb.String(), "\n")
}
