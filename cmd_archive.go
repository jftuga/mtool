package main

import (
	"flag"
	"github.com/jftuga/mtool/internal/archive"
)

func cmdArchive(args []string) error {
	fs := flag.NewFlagSet("archive", flag.ExitOnError)
	format := fs.String("format", "tar.gz", "archive format: tar.gz, tar.zlib, zip")
	output := fs.String("output", "", "output filename or directory")
	extract := fs.Bool("extract", false, "extract archive instead of creating one")
	fs.Parse(args)

	return archive.Run(
		archive.WithFormat(*format),
		archive.WithOutput(*output),
		archive.WithExtract(*extract),
		archive.WithFiles(fs.Args()),
	)
}
