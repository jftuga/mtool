package fetch

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mtool/internal/shared"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config holds configuration for the fetch command.
type Config struct {
	Method      string
	Header      string
	Body        string
	Timeout     time.Duration
	ShowHeaders bool
	DumpReq     bool
	Trace       bool
	Output      string
	URL         string
}

// Option configures a Config.
type Option func(*Config)

func WithMethod(method string) Option       { return func(c *Config) { c.Method = method } }
func WithHeader(header string) Option       { return func(c *Config) { c.Header = header } }
func WithBody(body string) Option           { return func(c *Config) { c.Body = body } }
func WithTimeout(d time.Duration) Option    { return func(c *Config) { c.Timeout = d } }
func WithShowHeaders(show bool) Option      { return func(c *Config) { c.ShowHeaders = show } }
func WithDumpReq(dump bool) Option          { return func(c *Config) { c.DumpReq = dump } }
func WithTrace(trace bool) Option           { return func(c *Config) { c.Trace = trace } }
func WithOutput(output string) Option       { return func(c *Config) { c.Output = output } }
func WithURL(u string) Option               { return func(c *Config) { c.URL = u } }

// Run fetches a URL and displays response details.
func Run(opts ...Option) error {
	cfg := &Config{Method: "GET", Timeout: 30 * time.Second}
	for _, o := range opts {
		o(cfg)
	}

	if cfg.URL == "" {
		return errors.New("usage: mtool fetch [options] <url>")
	}

	rawURL := cfg.URL
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme == "" {
		parsed.Scheme = "https"
		rawURL = parsed.String()
	}

	var bodyReader io.Reader
	if cfg.Body != "" {
		bodyReader = strings.NewReader(cfg.Body)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(cfg.Method), rawURL, bodyReader)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	// Set up httptrace if trace is enabled
	var traceInfo struct {
		dnsStart     time.Time
		dnsDone      time.Duration
		connectStart time.Time
		connectDone  time.Duration
		tlsStart     time.Time
		tlsDone      time.Duration
		gotFirstByte time.Duration
		requestStart time.Time
	}
	if cfg.Trace {
		traceCtx := &httptrace.ClientTrace{
			DNSStart: func(_ httptrace.DNSStartInfo) {
				traceInfo.dnsStart = time.Now()
			},
			DNSDone: func(_ httptrace.DNSDoneInfo) {
				traceInfo.dnsDone = time.Since(traceInfo.dnsStart)
			},
			ConnectStart: func(_, _ string) {
				traceInfo.connectStart = time.Now()
			},
			ConnectDone: func(_, _ string, _ error) {
				traceInfo.connectDone = time.Since(traceInfo.connectStart)
			},
			TLSHandshakeStart: func() {
				traceInfo.tlsStart = time.Now()
			},
			TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
				traceInfo.tlsDone = time.Since(traceInfo.tlsStart)
			},
			GotFirstResponseByte: func() {
				traceInfo.gotFirstByte = time.Since(traceInfo.requestStart)
			},
		}
		ctx = httptrace.WithClientTrace(ctx, traceCtx)
		req = req.WithContext(ctx)
	}

	if cfg.Header != "" {
		parts := strings.SplitN(cfg.Header, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	if cfg.DumpReq {
		dump, err := httputil.DumpRequestOut(req, true)
		if err == nil {
			fmt.Fprintf(os.Stderr, "%s\n", dump)
		}
	}

	traceInfo.requestStart = time.Now()
	start := traceInfo.requestStart
	jar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("creating cookie jar: %w", err)
	}
	client := &http.Client{Jar: jar, Timeout: cfg.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	elapsed := time.Since(start)

	fmt.Fprintf(os.Stderr, "HTTP/%d.%d %s (%.2fs)\n",
		resp.ProtoMajor, resp.ProtoMinor, resp.Status,
		elapsed.Seconds())

	if cfg.Trace {
		fmt.Fprintf(os.Stderr, "\nTrace:\n")
		if traceInfo.dnsDone > 0 {
			fmt.Fprintf(os.Stderr, "  DNS Lookup:    %s\n", traceInfo.dnsDone.Round(time.Microsecond))
		}
		if traceInfo.connectDone > 0 {
			fmt.Fprintf(os.Stderr, "  TCP Connect:   %s\n", traceInfo.connectDone.Round(time.Microsecond))
		}
		if traceInfo.tlsDone > 0 {
			fmt.Fprintf(os.Stderr, "  TLS Handshake: %s\n", traceInfo.tlsDone.Round(time.Microsecond))
		}
		if traceInfo.gotFirstByte > 0 {
			fmt.Fprintf(os.Stderr, "  TTFB:          %s\n", traceInfo.gotFirstByte.Round(time.Microsecond))
		}
		fmt.Fprintf(os.Stderr, "  Total:         %s\n", elapsed.Round(time.Microsecond))
		fmt.Fprintln(os.Stderr)
	}

	if cfg.ShowHeaders {
		for k, vals := range resp.Header {
			for _, v := range vals {
				fmt.Fprintf(os.Stderr, "%s: %s\n", k, v)
			}
		}
		fmt.Fprintln(os.Stderr)
	}

	var dest io.Writer = os.Stdout
	if cfg.Output != "" {
		f, err := os.Create(cfg.Output)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		dest = f
	}

	n, err := io.Copy(dest, resp.Body)
	if err != nil {
		return fmt.Errorf("reading body: %w", err)
	}
	fmt.Fprintf(os.Stderr, "\n(%s received)\n", shared.FormatSize(n))
	return nil
}
