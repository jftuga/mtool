package main

import (
	"flag"
	"github.com/jftuga/mtool/v2/internal/jsoncmd"
	"github.com/jftuga/mtool/v2/internal/shared"
)

func cmdJSON(args []string) error {
	fs := flag.NewFlagSet("json", flag.ExitOnError)
	mode := fs.String("mode", "pretty", "mode: pretty, compact, validate, query")
	query := fs.String("query", "", "dot-path query (e.g. .foo.bar, .items[0].name)")
	indent := fs.String("indent", "  ", "indentation string for pretty mode")
	fs.Parse(args)

	data, err := shared.ReadInput(fs.Args())
	if err != nil {
		return err
	}

	return jsoncmd.Run(
		jsoncmd.WithMode(*mode),
		jsoncmd.WithQuery(*query),
		jsoncmd.WithIndent(*indent),
		jsoncmd.WithInput(data),
	)
}
