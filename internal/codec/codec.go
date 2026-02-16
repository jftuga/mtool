package codec

import (
	"bytes"
	"encoding/ascii85"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"mime/quotedprintable"
	"net/url"
	"os"
	"strings"
	"unicode/utf16"
)

// Config holds configuration for encode/decode commands.
type Config struct {
	Format string
	Input  []byte
	Stdout io.Writer
}

// Option configures a Config.
type Option func(*Config)

func WithFormat(format string) Option { return func(c *Config) { c.Format = format } }
func WithInput(data []byte) Option    { return func(c *Config) { c.Input = data } }
func WithStdout(w io.Writer) Option   { return func(c *Config) { c.Stdout = w } }

// RunEncode encodes data in the specified format.
func RunEncode(opts ...Option) error {
	cfg := &Config{Format: "base64", Stdout: os.Stdout}
	for _, o := range opts {
		o(cfg)
	}

	input := cfg.Input

	switch cfg.Format {
	case "base64":
		fmt.Fprintln(cfg.Stdout, base64.StdEncoding.EncodeToString(input))
	case "base32":
		fmt.Fprintln(cfg.Stdout, base32.StdEncoding.EncodeToString(input))
	case "hex":
		fmt.Fprintln(cfg.Stdout, hex.EncodeToString(input))
	case "ascii85":
		dst := make([]byte, ascii85.MaxEncodedLen(len(input)))
		n := ascii85.Encode(dst, input)
		fmt.Fprintln(cfg.Stdout, string(dst[:n]))
	case "url":
		fmt.Fprintln(cfg.Stdout, url.QueryEscape(string(input)))
	case "html":
		fmt.Fprintln(cfg.Stdout, html.EscapeString(string(input)))
	case "qp":
		var buf bytes.Buffer
		w := quotedprintable.NewWriter(&buf)
		if _, err := w.Write(input); err != nil {
			return fmt.Errorf("quoted-printable encode: %w", err)
		}
		if err := w.Close(); err != nil {
			return fmt.Errorf("quoted-printable encode: %w", err)
		}
		fmt.Fprint(cfg.Stdout, buf.String())
	case "utf16":
		runes := []rune(string(input))
		encoded := utf16.Encode(runes)
		// Write as little-endian with BOM
		bom := []byte{0xFF, 0xFE}
		if w, ok := cfg.Stdout.(*os.File); ok {
			w.Write(bom)
			for _, u := range encoded {
				w.Write([]byte{byte(u), byte(u >> 8)})
			}
		} else {
			cfg.Stdout.Write(bom)
			for _, u := range encoded {
				cfg.Stdout.Write([]byte{byte(u), byte(u >> 8)})
			}
		}
	default:
		return fmt.Errorf("unknown format: %s", cfg.Format)
	}
	return nil
}

// RunDecode decodes data in the specified format.
func RunDecode(opts ...Option) error {
	cfg := &Config{Format: "base64", Stdout: os.Stdout}
	for _, o := range opts {
		o(cfg)
	}

	input := cfg.Input
	trimmed := strings.TrimSpace(string(input))

	switch cfg.Format {
	case "base64":
		decoded, err := base64.StdEncoding.DecodeString(trimmed)
		if err != nil {
			return fmt.Errorf("base64 decode: %w", err)
		}
		cfg.Stdout.Write(decoded)
	case "base32":
		decoded, err := base32.StdEncoding.DecodeString(trimmed)
		if err != nil {
			return fmt.Errorf("base32 decode: %w", err)
		}
		cfg.Stdout.Write(decoded)
	case "hex":
		decoded, err := hex.DecodeString(trimmed)
		if err != nil {
			return fmt.Errorf("hex decode: %w", err)
		}
		cfg.Stdout.Write(decoded)
	case "ascii85":
		dst := make([]byte, len(trimmed))
		ndst, _, err := ascii85.Decode(dst, []byte(trimmed), true)
		if err != nil {
			return fmt.Errorf("ascii85 decode: %w", err)
		}
		cfg.Stdout.Write(dst[:ndst])
	case "url":
		decoded, err := url.QueryUnescape(trimmed)
		if err != nil {
			return fmt.Errorf("url decode: %w", err)
		}
		fmt.Fprintln(cfg.Stdout, decoded)
	case "html":
		fmt.Fprintln(cfg.Stdout, html.UnescapeString(trimmed))
	case "qp":
		r := quotedprintable.NewReader(strings.NewReader(trimmed))
		decoded, err := io.ReadAll(r)
		if err != nil {
			return fmt.Errorf("quoted-printable decode: %w", err)
		}
		cfg.Stdout.Write(decoded)
	case "utf16":
		raw := input
		// Strip BOM if present (little-endian or big-endian)
		littleEndian := true
		if len(raw) >= 2 {
			if raw[0] == 0xFF && raw[1] == 0xFE {
				raw = raw[2:]
			} else if raw[0] == 0xFE && raw[1] == 0xFF {
				raw = raw[2:]
				littleEndian = false
			}
		}
		if len(raw)%2 != 0 {
			return errors.New("utf16 decode: input has odd number of bytes")
		}
		u16 := make([]uint16, len(raw)/2)
		for i := range u16 {
			if littleEndian {
				u16[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
			} else {
				u16[i] = uint16(raw[2*i])<<8 | uint16(raw[2*i+1])
			}
		}
		runes := utf16.Decode(u16)
		fmt.Fprintln(cfg.Stdout, string(runes))
	default:
		return fmt.Errorf("unknown format: %s", cfg.Format)
	}
	return nil
}
