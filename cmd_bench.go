package main

import (
	"errors"
	"flag"
	"github.com/jftuga/mtool/v2/internal/bench"
	"time"
)

func cmdBench(args []string) error {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	requests := fs.Int("n", 100, "total requests")
	concurrency := fs.Int("c", 10, "concurrent workers")
	timeout := fs.Duration("timeout", 10*time.Second, "request timeout")
	method := fs.String("method", "GET", "HTTP method")
	jitter := fs.Duration("jitter", 0, "max random delay before each request (e.g. 100ms)")
	fs.Parse(args)

	if fs.NArg() < 1 {
		return errors.New("usage: mtool bench [options] <url>")
	}

	return bench.Run(
		bench.WithURL(fs.Arg(0)),
		bench.WithRequests(*requests),
		bench.WithConcurrency(*concurrency),
		bench.WithTimeout(*timeout),
		bench.WithMethod(*method),
		bench.WithJitter(*jitter),
	)
}
