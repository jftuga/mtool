package main

import (
	"flag"
	"mtool/internal/generate"
)

func cmdGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	mode := fs.String("mode", "password", "mode: password, token, bytes, uuid, bigint")
	length := fs.Int("length", 20, "length of generated output")
	count := fs.Int("count", 1, "number of items to generate")
	charset := fs.String("charset", "full", "charset for password: alpha, alnum, full")
	fs.Parse(args)

	return generate.Run(
		generate.WithMode(*mode),
		generate.WithLength(*length),
		generate.WithCount(*count),
		generate.WithCharset(*charset),
	)
}
