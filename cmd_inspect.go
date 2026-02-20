package main

import (
	"errors"
	"flag"
	"github.com/jftuga/mtool/internal/inspect"
)

func cmdInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	mode := fs.String("mode", "tls", "inspection mode: tls, dns")
	port := fs.String("port", "443", "port for TLS connection")
	fs.Parse(args)

	if fs.NArg() < 1 {
		return errors.New("usage: mtool inspect [options] <host>")
	}

	return inspect.Run(
		inspect.WithMode(*mode),
		inspect.WithPort(*port),
		inspect.WithHost(fs.Arg(0)),
	)
}
