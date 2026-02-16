package netcmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// Config holds configuration for the net command.
type Config struct {
	Mode      string
	Timeout   time.Duration
	StartPort int
	EndPort   int
	Addr      string
	Host      string
	Stdout    io.Writer
	Stderr    io.Writer
}

// Option configures a Config.
type Option func(*Config)

func WithMode(mode string) Option          { return func(c *Config) { c.Mode = mode } }
func WithTimeout(d time.Duration) Option   { return func(c *Config) { c.Timeout = d } }
func WithStartPort(p int) Option           { return func(c *Config) { c.StartPort = p } }
func WithEndPort(p int) Option             { return func(c *Config) { c.EndPort = p } }
func WithAddr(addr string) Option          { return func(c *Config) { c.Addr = addr } }
func WithHost(host string) Option          { return func(c *Config) { c.Host = host } }
func WithStdout(w io.Writer) Option        { return func(c *Config) { c.Stdout = w } }
func WithStderr(w io.Writer) Option        { return func(c *Config) { c.Stderr = w } }

// Run executes network utilities.
func Run(opts ...Option) error {
	cfg := &Config{Mode: "check", Timeout: 5 * time.Second, StartPort: 1, EndPort: 1024, Addr: ":0", Stdout: os.Stdout, Stderr: os.Stderr}
	for _, o := range opts {
		o(cfg)
	}

	switch cfg.Mode {
	case "check":
		if cfg.Host == "" {
			return errors.New("usage: mtool net -mode check <host:port>")
		}
		dur, err := NetCheck(cfg.Host, cfg.Timeout)
		if err != nil {
			fmt.Fprintf(cfg.Stdout, "CLOSED %s (%v)\n", cfg.Host, err)
			return err
		}
		fmt.Fprintf(cfg.Stdout, "OPEN %s (connected in %s)\n", cfg.Host, dur.Round(time.Microsecond))
		return nil
	case "scan":
		if cfg.Host == "" {
			return errors.New("usage: mtool net -mode scan -start N -end M <host>")
		}
		openPorts, err := NetScan(cfg.Host, cfg.StartPort, cfg.EndPort, cfg.Timeout)
		if err != nil {
			return err
		}
		if len(openPorts) == 0 {
			fmt.Fprintf(cfg.Stdout, "No open ports found on %s (%d-%d)\n", cfg.Host, cfg.StartPort, cfg.EndPort)
		} else {
			fmt.Fprintf(cfg.Stdout, "Open ports on %s:\n", cfg.Host)
			for _, p := range openPorts {
				fmt.Fprintf(cfg.Stdout, "  %d\n", p)
			}
		}
		return nil
	case "wait":
		if cfg.Host == "" {
			return errors.New("usage: mtool net -mode wait -timeout <duration> <host:port>")
		}
		fmt.Fprintf(cfg.Stderr, "Waiting for %s (timeout %s)...\n", cfg.Host, cfg.Timeout)
		if err := NetWait(cfg.Host, cfg.Timeout); err != nil {
			return err
		}
		fmt.Fprintf(cfg.Stdout, "OK %s is reachable\n", cfg.Host)
		return nil
	case "echo":
		return NetEcho(cfg.Addr, cfg.Timeout)
	default:
		return fmt.Errorf("unknown mode: %s", cfg.Mode)
	}
}

// NetCheck checks if a TCP port is open.
func NetCheck(address string, timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return 0, err
	}
	conn.Close()
	return time.Since(start), nil
}

// NetScan scans a port range on a host.
func NetScan(host string, start, end int, timeout time.Duration) ([]int, error) {
	if start < 1 || end > 65535 || start > end {
		return nil, fmt.Errorf("invalid port range: %d-%d", start, end)
	}

	var mu sync.Mutex
	var openPorts []int
	var wg sync.WaitGroup
	sem := make(chan struct{}, 100)

	for port := start; port <= end; port++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			address := net.JoinHostPort(host, strconv.Itoa(p))
			conn, err := net.DialTimeout("tcp", address, timeout)
			if err == nil {
				conn.Close()
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()

	sort.Ints(openPorts)
	return openPorts, nil
}

// NetWait waits for a TCP port to become available.
func NetWait(address string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s after %s", address, timeout)
}

// NetEcho starts a TCP echo server.
func NetEcho(addr string, timeout time.Duration) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening: %w", err)
	}
	defer ln.Close()

	actualAddr := ln.Addr().String()
	fmt.Fprintf(os.Stderr, "Echo server listening on %s\n", actualAddr)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("accepting: %w", err)
			}
		}
		go func(c net.Conn) {
			defer c.Close()
			io.Copy(c, c)
		}(conn)
	}
}
