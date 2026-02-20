package main

import (
	"errors"
	"flag"
	"github.com/jftuga/mtool/internal/fetch"
	"time"
)

func cmdFetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	method := fs.String("method", "GET", "HTTP method")
	headerFlag := fs.String("header", "", "additional header (Key: Value)")
	body := fs.String("body", "", "request body")
	timeout := fs.Duration("timeout", 30*time.Second, "request timeout")
	showHeaders := fs.Bool("headers", false, "show response headers")
	dumpReq := fs.Bool("dump", false, "dump raw request")
	trace := fs.Bool("trace", false, "show timing breakdown (DNS, TLS, TTFB)")
	output := fs.String("output", "", "write body to file instead of stdout")
	fs.Parse(args)

	if fs.NArg() < 1 {
		return errors.New("usage: mtool fetch [options] <url>")
	}

	return fetch.Run(
		fetch.WithMethod(*method),
		fetch.WithHeader(*headerFlag),
		fetch.WithBody(*body),
		fetch.WithTimeout(*timeout),
		fetch.WithShowHeaders(*showHeaders),
		fetch.WithDumpReq(*dumpReq),
		fetch.WithTrace(*trace),
		fetch.WithOutput(*output),
		fetch.WithURL(fs.Arg(0)),
	)
}
