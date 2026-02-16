package jsoncmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Config holds configuration for the JSON command.
type Config struct {
	Mode   string
	Query  string
	Indent string
	Input  []byte
	Stdout io.Writer
}

// Option configures a Config.
type Option func(*Config)

func WithMode(mode string) Option     { return func(c *Config) { c.Mode = mode } }
func WithQuery(query string) Option   { return func(c *Config) { c.Query = query } }
func WithIndent(indent string) Option { return func(c *Config) { c.Indent = indent } }
func WithInput(data []byte) Option    { return func(c *Config) { c.Input = data } }
func WithStdout(w io.Writer) Option   { return func(c *Config) { c.Stdout = w } }

// Run processes JSON data.
func Run(opts ...Option) error {
	cfg := &Config{Mode: "pretty", Indent: "  ", Stdout: os.Stdout}
	for _, o := range opts {
		o(cfg)
	}

	data := cfg.Input

	switch cfg.Mode {
	case "pretty":
		result, err := JSONPretty(data, cfg.Indent)
		if err != nil {
			return err
		}
		fmt.Fprintln(cfg.Stdout, result)
	case "compact":
		result, err := JSONCompact(data)
		if err != nil {
			return err
		}
		fmt.Fprintln(cfg.Stdout, result)
	case "validate":
		if json.Valid(data) {
			fmt.Fprintln(cfg.Stdout, "valid")
		} else {
			fmt.Fprintln(cfg.Stdout, "invalid")
			return errors.New("invalid JSON")
		}
	case "query":
		if cfg.Query == "" {
			return errors.New("-query is required for query mode")
		}
		result, err := JSONQuery(data, cfg.Query)
		if err != nil {
			return err
		}
		switch v := result.(type) {
		case map[string]interface{}, []interface{}:
			out, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(cfg.Stdout, string(out))
		default:
			fmt.Fprintln(cfg.Stdout, v)
		}
	default:
		return fmt.Errorf("unknown mode: %s", cfg.Mode)
	}
	return nil
}

// JSONPretty pretty-prints JSON with custom indentation.
func JSONPretty(data []byte, indent string) (string, error) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, data, "", indent); err != nil {
		return "", fmt.Errorf("pretty-printing JSON: %w", err)
	}
	return buf.String(), nil
}

// JSONCompact compacts JSON to a single line.
func JSONCompact(data []byte) (string, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, data); err != nil {
		return "", fmt.Errorf("compacting JSON: %w", err)
	}
	return buf.String(), nil
}

// JSONQuery queries JSON using dot-notation paths.
func JSONQuery(data []byte, path string) (interface{}, error) {
	var root interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	path = strings.TrimPrefix(path, ".")
	if path == "" {
		return root, nil
	}

	current := root
	parts := splitJSONPath(path)
	for _, part := range parts {
		if idx := strings.Index(part, "["); idx >= 0 {
			key := part[:idx]
			indexStr := strings.TrimSuffix(part[idx+1:], "]")
			arrayIdx, err := strconv.Atoi(indexStr)
			if err != nil {
				return nil, fmt.Errorf("invalid array index: %s", part)
			}
			if key != "" {
				obj, ok := current.(map[string]interface{})
				if !ok {
					return nil, fmt.Errorf("expected object at %q, got %T", key, current)
				}
				current, ok = obj[key]
				if !ok {
					return nil, fmt.Errorf("key not found: %q", key)
				}
			}
			arr, ok := current.([]interface{})
			if !ok {
				return nil, fmt.Errorf("expected array at %q, got %T", part, current)
			}
			if arrayIdx < 0 || arrayIdx >= len(arr) {
				return nil, fmt.Errorf("array index %d out of range (len=%d)", arrayIdx, len(arr))
			}
			current = arr[arrayIdx]
		} else {
			obj, ok := current.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("expected object at %q, got %T", part, current)
			}
			current, ok = obj[part]
			if !ok {
				return nil, fmt.Errorf("key not found: %q", part)
			}
		}
	}
	return current, nil
}

func splitJSONPath(path string) []string {
	var parts []string
	var current strings.Builder
	for i := 0; i < len(path); i++ {
		if path[i] == '.' && (current.Len() > 0 || i == 0) {
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		} else {
			current.WriteByte(path[i])
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}
