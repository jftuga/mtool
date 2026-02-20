package main

import (
	"flag"
	"github.com/jftuga/mtool/v2/internal/timecmd"
)

func cmdTime(args []string) error {
	fs := flag.NewFlagSet("time", flag.ExitOnError)
	mode := fs.String("mode", "now", "mode: now, toepoch, fromepoch, convert")
	format := fs.String("format", "", "Go time layout for output (e.g. 2006-01-02)")
	zone := fs.String("zone", "", "timezone name (e.g. America/New_York)")
	fs.Parse(args)

	return timecmd.Run(
		timecmd.WithMode(*mode),
		timecmd.WithFormat(*format),
		timecmd.WithZone(*zone),
		timecmd.WithArgs(fs.Args()),
	)
}
