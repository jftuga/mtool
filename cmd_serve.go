package main

import (
	"flag"
	"github.com/jftuga/mtool/v2/internal/serve"
)

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "listen address")
	dir := fs.String("dir", ".", "directory to serve")
	enableGzip := fs.Bool("gzip", false, "enable gzip compression")
	enableTLS := fs.Bool("tls", false, "enable HTTPS with an auto-generated self-signed certificate")
	fs.Parse(args)

	return serve.Run(
		serve.WithAddr(*addr),
		serve.WithDir(*dir),
		serve.WithGzip(*enableGzip),
		serve.WithTLS(*enableTLS),
	)
}
