package main

import (
	"flag"
	"mtool/internal/shared"
	"mtool/internal/transform"
)

func cmdTransform(args []string) error {
	fs := flag.NewFlagSet("transform", flag.ExitOnError)
	mode := fs.String("mode", "upper", "transform: upper, lower, title, reverse, count, replace, grep, uniq, freq, sort")
	pattern := fs.String("pattern", "", "regex pattern for replace/grep")
	replacement := fs.String("replacement", "", "replacement string for replace mode")
	numeric := fs.Bool("numeric", false, "sort numerically instead of lexicographically (sort mode)")
	descending := fs.Bool("reverse", false, "sort in descending order (sort mode)")
	ignoreCase := fs.Bool("ignore-case", false, "case-insensitive sort (sort mode)")
	sortField := fs.Int("field", 0, "sort by 1-indexed whitespace-delimited field, 0 = whole line (sort mode)")
	fs.Parse(args)

	input, err := shared.ReadInput(fs.Args())
	if err != nil {
		return err
	}

	return transform.Run(
		transform.WithMode(*mode),
		transform.WithPattern(*pattern),
		transform.WithReplacement(*replacement),
		transform.WithNumeric(*numeric),
		transform.WithDescending(*descending),
		transform.WithIgnoreCase(*ignoreCase),
		transform.WithSortField(*sortField),
		transform.WithInput(input),
	)
}
