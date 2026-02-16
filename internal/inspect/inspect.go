package inspect

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"
)

// Config holds configuration for the inspect command.
type Config struct {
	Mode   string
	Port   string
	Host   string
	Stdout io.Writer
}

// Option configures a Config.
type Option func(*Config)

func WithMode(mode string) Option   { return func(c *Config) { c.Mode = mode } }
func WithPort(port string) Option   { return func(c *Config) { c.Port = port } }
func WithHost(host string) Option   { return func(c *Config) { c.Host = host } }
func WithStdout(w io.Writer) Option { return func(c *Config) { c.Stdout = w } }

// Run executes TLS or DNS inspection.
func Run(opts ...Option) error {
	cfg := &Config{Mode: "tls", Port: "443", Stdout: os.Stdout}
	for _, o := range opts {
		o(cfg)
	}

	if cfg.Host == "" {
		return errors.New("usage: mtool inspect [options] <host>")
	}

	switch cfg.Mode {
	case "tls":
		return inspectTLS(cfg.Host, cfg.Port, cfg.Stdout)
	case "dns":
		return inspectDNS(cfg.Host, cfg.Stdout)
	default:
		return fmt.Errorf("unknown mode: %s", cfg.Mode)
	}
}

func inspectTLS(host, port string, w io.Writer) error {
	addr := net.JoinHostPort(host, port)
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp", addr,
		&tls.Config{},
	)
	if err != nil {
		return fmt.Errorf("TLS connection to %s: %w", addr, err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	fmt.Fprintf(w, "TLS %s connected to %s\n\n", TLSVersionString(state.Version), addr)
	fmt.Fprintf(w, "Cipher Suite: %s\n", tls.CipherSuiteName(state.CipherSuite))
	fmt.Fprintf(w, "ALPN Protocol: %s\n", state.NegotiatedProtocol)

	for i, cert := range state.PeerCertificates {
		fmt.Fprintf(w, "\nCertificate #%d:\n", i+1)
		fmt.Fprintf(w, "  Subject:    %s\n", cert.Subject.String())
		fmt.Fprintf(w, "  Issuer:     %s\n", cert.Issuer.String())
		fmt.Fprintf(w, "  Serial:     %s\n", cert.SerialNumber.String())
		fmt.Fprintf(w, "  Not Before: %s\n", cert.NotBefore.Format(time.RFC3339))
		fmt.Fprintf(w, "  Not After:  %s\n", cert.NotAfter.Format(time.RFC3339))

		daysLeft := time.Until(cert.NotAfter).Hours() / 24
		fmt.Fprintf(w, "  Expires In: %.0f days\n", daysLeft)

		if len(cert.DNSNames) > 0 {
			fmt.Fprintf(w, "  DNS Names:  %s\n", strings.Join(cert.DNSNames, ", "))
		}
		if len(cert.IPAddresses) > 0 {
			ips := make([]string, len(cert.IPAddresses))
			for j, ip := range cert.IPAddresses {
				ips[j] = ip.String()
			}
			fmt.Fprintf(w, "  IP Addrs:   %s\n", strings.Join(ips, ", "))
		}

		// Print PEM
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})

		// Verify against system roots
		opts := x509.VerifyOptions{DNSName: host}
		if _, err := cert.Verify(opts); err != nil && i == 0 {
			fmt.Fprintf(w, "  Verify:     FAILED (%s)\n", err)
		} else if i == 0 {
			fmt.Fprintf(w, "  Verify:     OK\n")
		}
		_ = pemBlock
	}

	return nil
}

// TLSVersionString converts a TLS version number to a human-readable string.
func TLSVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return strconv.FormatUint(uint64(v), 16)
	}
}

func inspectDNS(host string, w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	defer tw.Flush()

	fmt.Fprintf(tw, "DNS lookup for %s\n\n", host)

	// A/AAAA records
	ips, err := net.LookupHost(host)
	if err == nil && len(ips) > 0 {
		fmt.Fprintf(tw, "Addresses:\n")
		for _, ip := range ips {
			addr, err := netip.ParseAddr(ip)
			version := "IPv4"
			if err == nil && addr.Is6() {
				version = "IPv6"
			}
			fmt.Fprintf(tw, "  %s\t(%s)\n", ip, version)
		}
	}

	// MX records
	mxs, err := net.LookupMX(host)
	if err == nil && len(mxs) > 0 {
		fmt.Fprintf(tw, "\nMX Records:\n")
		for _, mx := range mxs {
			fmt.Fprintf(tw, "  %s\tpriority=%d\n", mx.Host, mx.Pref)
		}
	}

	// TXT records
	txts, err := net.LookupTXT(host)
	if err == nil && len(txts) > 0 {
		fmt.Fprintf(tw, "\nTXT Records:\n")
		for _, txt := range txts {
			if utf8.RuneCountInString(txt) > 80 {
				txt = string([]rune(txt)[:80]) + "..."
			}
			fmt.Fprintf(tw, "  %s\n", txt)
		}
	}

	// NS records
	nss, err := net.LookupNS(host)
	if err == nil && len(nss) > 0 {
		fmt.Fprintf(tw, "\nNS Records:\n")
		for _, ns := range nss {
			fmt.Fprintf(tw, "  %s\n", ns.Host)
		}
	}

	// CNAME
	cname, err := net.LookupCNAME(host)
	if err == nil && cname != host+"." {
		fmt.Fprintf(tw, "\nCNAME:\t%s\n", cname)
	}

	return nil
}
