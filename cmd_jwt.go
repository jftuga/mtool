package main

import (
	"flag"
	"mtool/internal/jwt"
)

func cmdJWT(args []string) error {
	fs := flag.NewFlagSet("jwt", flag.ExitOnError)
	raw := fs.Bool("raw", false, "output compact JSON instead of pretty-printed")
	fs.Parse(args)

	if fs.NArg() < 1 {
		return jwt.Run() // will return usage error
	}

	return jwt.Run(
		jwt.WithRaw(*raw),
		jwt.WithToken(fs.Arg(0)),
	)
}
