package main

import (
	"flag"
	"github.com/jftuga/mtool/internal/info"
)

func cmdInfo(args []string) error {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	format := fs.String("format", "table", "output format: table, json, xml, csv")
	showEnv := fs.Bool("env", false, "include environment variables")
	fs.Parse(args)

	return info.Run(
		info.WithFormat(*format),
		info.WithShowEnv(*showEnv),
	)
}
