package timecmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds configuration for the time command.
type Config struct {
	Mode   string
	Format string
	Zone   string
	Args   []string
	Stdout io.Writer
}

// Option configures a Config.
type Option func(*Config)

func WithMode(mode string) Option     { return func(c *Config) { c.Mode = mode } }
func WithFormat(format string) Option { return func(c *Config) { c.Format = format } }
func WithZone(zone string) Option     { return func(c *Config) { c.Zone = zone } }
func WithArgs(args []string) Option   { return func(c *Config) { c.Args = args } }
func WithStdout(w io.Writer) Option   { return func(c *Config) { c.Stdout = w } }

// Run executes the time command.
func Run(opts ...Option) error {
	cfg := &Config{Mode: "now", Stdout: os.Stdout}
	for _, o := range opts {
		o(cfg)
	}

	switch cfg.Mode {
	case "now":
		fmt.Fprintln(cfg.Stdout, FormatMultiTime(time.Now()))
		return nil
	case "fromepoch":
		if len(cfg.Args) < 1 {
			return errors.New("usage: mtool time -mode fromepoch <epoch_seconds>")
		}
		epoch, err := strconv.ParseInt(cfg.Args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid epoch: %w", err)
		}
		t := time.Unix(epoch, 0)
		if cfg.Format != "" {
			fmt.Fprintln(cfg.Stdout, t.Format(cfg.Format))
		} else {
			fmt.Fprintln(cfg.Stdout, FormatMultiTime(t))
		}
		return nil
	case "toepoch":
		if len(cfg.Args) < 1 {
			return errors.New("usage: mtool time -mode toepoch <date_string>")
		}
		t, err := ParseFlexibleTime(cfg.Args[0])
		if err != nil {
			return err
		}
		fmt.Fprintln(cfg.Stdout, t.Unix())
		return nil
	case "convert":
		if len(cfg.Args) < 1 {
			return errors.New("usage: mtool time -mode convert -zone <timezone> <date_string>")
		}
		if cfg.Zone == "" {
			return errors.New("-zone is required for convert mode")
		}
		t, err := ParseFlexibleTime(cfg.Args[0])
		if err != nil {
			return err
		}
		loc, err := time.LoadLocation(cfg.Zone)
		if err != nil {
			return fmt.Errorf("loading timezone: %w", err)
		}
		converted := t.In(loc)
		if cfg.Format != "" {
			fmt.Fprintln(cfg.Stdout, converted.Format(cfg.Format))
		} else {
			fmt.Fprintln(cfg.Stdout, FormatMultiTime(converted))
		}
		return nil
	default:
		return fmt.Errorf("unknown mode: %s", cfg.Mode)
	}
}

// ParseFlexibleTime parses various time string formats.
func ParseFlexibleTime(s string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"01/02/2006 15:04:05",
		"01/02/2006",
		"Jan 2, 2006 15:04:05",
		"Jan 2, 2006",
		"January 2, 2006 15:04:05",
		"January 2, 2006",
		"02 Jan 2006 15:04:05",
		"02 Jan 2006",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	// Try as epoch seconds
	if epoch, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(epoch, 0), nil
	}
	return time.Time{}, fmt.Errorf("unable to parse time: %q", s)
}

// FormatMultiTime formats time in multiple representations.
func FormatMultiTime(t time.Time) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Local:   %s\n", t.Local().Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&sb, "UTC:     %s\n", t.UTC().Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&sb, "RFC3339: %s\n", t.Format(time.RFC3339))
	fmt.Fprintf(&sb, "Epoch:   %d", t.Unix())
	return sb.String()
}
