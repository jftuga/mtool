package bench

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Config holds configuration for the bench command.
type Config struct {
	URL         string
	Requests    int
	Concurrency int
	Timeout     time.Duration
	Method      string
	Jitter      time.Duration
	Stdout      io.Writer
}

// Option configures a Config.
type Option func(*Config)

func WithURL(url string) Option            { return func(c *Config) { c.URL = url } }
func WithRequests(n int) Option            { return func(c *Config) { c.Requests = n } }
func WithConcurrency(n int) Option         { return func(c *Config) { c.Concurrency = n } }
func WithTimeout(d time.Duration) Option   { return func(c *Config) { c.Timeout = d } }
func WithMethod(method string) Option      { return func(c *Config) { c.Method = method } }
func WithJitter(d time.Duration) Option    { return func(c *Config) { c.Jitter = d } }
func WithStdout(w io.Writer) Option        { return func(c *Config) { c.Stdout = w } }

// Run benchmarks an HTTP endpoint.
func Run(opts ...Option) error {
	cfg := &Config{Requests: 100, Concurrency: 10, Timeout: 10 * time.Second, Method: "GET", Stdout: os.Stdout}
	for _, o := range opts {
		o(cfg)
	}

	if cfg.URL == "" {
		return errors.New("usage: mtool bench [options] <url>")
	}

	// Track recent errors with container/list
	recentErrors := list.New()
	var recentMu sync.Mutex

	var (
		wg        sync.WaitGroup
		completed atomic.Int64
		failed    atomic.Int64
		mu        sync.Mutex
		latencies []float64
	)

	client := &http.Client{Timeout: cfg.Timeout}
	sem := make(chan struct{}, cfg.Concurrency)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()

	for i := range cfg.Requests {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()

			if cfg.Jitter > 0 {
				time.Sleep(mrand.N(cfg.Jitter))
			}

			req, err := http.NewRequestWithContext(ctx, cfg.Method, cfg.URL, nil)
			if err != nil {
				failed.Add(1)
				return
			}

			reqStart := time.Now()
			resp, err := client.Do(req)
			lat := time.Since(reqStart).Seconds() * 1000

			if err != nil {
				failed.Add(1)
				recentMu.Lock()
				recentErrors.PushBack(err.Error())
				if recentErrors.Len() > 5 {
					recentErrors.Remove(recentErrors.Front())
				}
				recentMu.Unlock()
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			completed.Add(1)
			mu.Lock()
			latencies = append(latencies, lat)
			mu.Unlock()

			_ = idx
		}(i)
	}

	wg.Wait()
	totalDuration := time.Since(start)

	// Statistics
	sort.Float64s(latencies)
	n := len(latencies)

	fmt.Fprintf(cfg.Stdout, "\nBenchmark: %s %s\n", cfg.Method, cfg.URL)
	fmt.Fprintf(cfg.Stdout, "Completed: %d, Failed: %d\n", completed.Load(), failed.Load())
	fmt.Fprintf(cfg.Stdout, "Total time: %.2fs\n", totalDuration.Seconds())

	if n > 0 {
		var sum float64
		for _, l := range latencies {
			sum += l
		}
		mean := sum / float64(n)

		var variance float64
		for _, l := range latencies {
			diff := l - mean
			variance += diff * diff
		}
		stddev := math.Sqrt(variance / float64(n))

		fmt.Fprintf(cfg.Stdout, "Requests/sec: %.2f\n", float64(completed.Load())/totalDuration.Seconds())
		fmt.Fprintf(cfg.Stdout, "Latency (ms): min=%.2f, mean=%.2f, p50=%.2f, p95=%.2f, p99=%.2f, max=%.2f, stddev=%.2f\n",
			latencies[0],
			mean,
			Percentile(latencies, 50),
			Percentile(latencies, 95),
			Percentile(latencies, 99),
			latencies[n-1],
			stddev,
		)
	}

	// Show recent errors
	recentMu.Lock()
	if recentErrors.Len() > 0 {
		fmt.Fprintln(cfg.Stdout, "\nRecent errors:")
		for e := recentErrors.Front(); e != nil; e = e.Next() {
			fmt.Fprintf(cfg.Stdout, "  - %s\n", e.Value)
		}
	}
	recentMu.Unlock()

	return nil
}

// Percentile calculates the p-th percentile from a sorted slice.
func Percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
