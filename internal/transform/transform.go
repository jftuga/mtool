package transform

import (
	"bufio"
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"unicode"
	"unicode/utf8"
)

// Config holds configuration for the transform command.
type Config struct {
	Mode        string
	Pattern     string
	Replacement string
	Numeric     bool
	Descending  bool
	IgnoreCase  bool
	SortField   int
	Input       []byte
	Stdout      io.Writer
}

// Option configures a Config.
type Option func(*Config)

func WithMode(mode string) Option             { return func(c *Config) { c.Mode = mode } }
func WithPattern(pattern string) Option       { return func(c *Config) { c.Pattern = pattern } }
func WithReplacement(repl string) Option      { return func(c *Config) { c.Replacement = repl } }
func WithNumeric(numeric bool) Option         { return func(c *Config) { c.Numeric = numeric } }
func WithDescending(descending bool) Option   { return func(c *Config) { c.Descending = descending } }
func WithIgnoreCase(ignoreCase bool) Option   { return func(c *Config) { c.IgnoreCase = ignoreCase } }
func WithSortField(field int) Option          { return func(c *Config) { c.SortField = field } }
func WithInput(data []byte) Option            { return func(c *Config) { c.Input = data } }
func WithStdout(w io.Writer) Option           { return func(c *Config) { c.Stdout = w } }

// Run executes the text transformation.
func Run(opts ...Option) error {
	cfg := &Config{Mode: "upper", Stdout: os.Stdout}
	for _, o := range opts {
		o(cfg)
	}

	text := string(cfg.Input)

	switch cfg.Mode {
	case "upper":
		fmt.Fprint(cfg.Stdout, strings.ToUpper(text))
	case "lower":
		fmt.Fprint(cfg.Stdout, strings.ToLower(text))
	case "title":
		fmt.Fprint(cfg.Stdout, strings.ToTitle(text))
	case "reverse":
		runes := []rune(text)
		slices.Reverse(runes)
		fmt.Fprint(cfg.Stdout, string(runes))
	case "count":
		PrintTextStats(text, cfg.Stdout)
	case "replace":
		if cfg.Pattern == "" {
			return errors.New("-pattern is required for replace mode")
		}
		re, err := regexp.Compile(cfg.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex: %w", err)
		}
		fmt.Fprint(cfg.Stdout, re.ReplaceAllString(text, cfg.Replacement))
	case "grep":
		if cfg.Pattern == "" {
			return errors.New("-pattern is required for grep mode")
		}
		re, err := regexp.Compile(cfg.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex: %w", err)
		}
		scanner := bufio.NewScanner(strings.NewReader(text))
		for scanner.Scan() {
			line := scanner.Text()
			if re.MatchString(line) {
				fmt.Fprintln(cfg.Stdout, line)
			}
		}
	case "uniq":
		seen := make(map[string]bool)
		scanner := bufio.NewScanner(strings.NewReader(text))
		for scanner.Scan() {
			line := scanner.Text()
			if !seen[line] {
				seen[line] = true
				fmt.Fprintln(cfg.Stdout, line)
			}
		}
	case "freq":
		PrintWordFrequency(text, cfg.Stdout)
	case "sort":
		SortLines(text, cfg.Numeric, cfg.Descending, cfg.IgnoreCase, cfg.SortField, cfg.Stdout)
	default:
		return fmt.Errorf("unknown mode: %s", cfg.Mode)
	}
	return nil
}

// PrintTextStats prints text statistics.
func PrintTextStats(text string, w io.Writer) {
	lines := strings.Count(text, "\n")
	if len(text) > 0 && !strings.HasSuffix(text, "\n") {
		lines++
	}
	words := len(strings.Fields(text))
	chars := utf8.RuneCountInString(text)
	byteCount := len(text)

	letterCount := 0
	digitCount := 0
	spaceCount := 0
	for _, r := range text {
		switch {
		case unicode.IsLetter(r):
			letterCount++
		case unicode.IsDigit(r):
			digitCount++
		case unicode.IsSpace(r):
			spaceCount++
		}
	}

	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	fmt.Fprintf(tw, "Lines:\t%d\n", lines)
	fmt.Fprintf(tw, "Words:\t%d\n", words)
	fmt.Fprintf(tw, "Characters:\t%d\n", chars)
	fmt.Fprintf(tw, "Bytes:\t%d\n", byteCount)
	fmt.Fprintf(tw, "Letters:\t%d\n", letterCount)
	fmt.Fprintf(tw, "Digits:\t%d\n", digitCount)
	fmt.Fprintf(tw, "Spaces:\t%d\n", spaceCount)
	tw.Flush()
}

// PrintWordFrequency prints top 30 words by frequency.
func PrintWordFrequency(text string, w io.Writer) {
	wordRe := regexp.MustCompile(`\w+`)
	matches := wordRe.FindAllString(text, -1)

	freq := make(map[string]int)
	for _, word := range matches {
		freq[strings.ToLower(word)]++
	}

	type wordCount struct {
		Word  string
		Count int
	}
	var wcs []wordCount
	for word, c := range freq {
		wcs = append(wcs, wordCount{word, c})
	}
	slices.SortFunc(wcs, func(a, b wordCount) int {
		if a.Count != b.Count {
			return cmp.Compare(b.Count, a.Count) // descending
		}
		return cmp.Compare(a.Word, b.Word)
	})

	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	fmt.Fprintf(tw, "WORD\tCOUNT\n")
	limit := 30
	if len(wcs) < limit {
		limit = len(wcs)
	}
	for _, wc := range wcs[:limit] {
		fmt.Fprintf(tw, "%s\t%d\n", wc.Word, wc.Count)
	}
	tw.Flush()
}

// SortLines sorts lines of text.
func SortLines(text string, numeric, descending, ignoreCase bool, field int, w io.Writer) {
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")

	extractKey := func(line string) string {
		if field <= 0 {
			return line
		}
		fields := strings.Fields(line)
		if field-1 >= len(fields) {
			return ""
		}
		return fields[field-1]
	}

	slices.SortStableFunc(lines, func(a, b string) int {
		keyA, keyB := extractKey(a), extractKey(b)

		var result int
		if numeric {
			na, errA := strconv.ParseFloat(keyA, 64)
			nb, errB := strconv.ParseFloat(keyB, 64)
			if errA != nil && errB != nil {
				result = cmp.Compare(keyA, keyB)
			} else if errA != nil {
				result = 1
			} else if errB != nil {
				result = -1
			} else {
				result = cmp.Compare(na, nb)
			}
		} else {
			if ignoreCase {
				keyA, keyB = strings.ToLower(keyA), strings.ToLower(keyB)
			}
			result = cmp.Compare(keyA, keyB)
		}

		if descending {
			result = -result
		}
		return result
	})

	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
}
