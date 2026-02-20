package main

import (
	"errors"
	"flag"
	"github.com/jftuga/mtool/internal/imgconv"
)

func cmdImage(args []string) error {
	fs := flag.NewFlagSet("image", flag.ExitOnError)
	format := fs.String("format", "", "output format: png, jpg, gif (default: inferred from output filename)")
	quality := fs.Int("quality", 90, "JPEG quality 1-100 (only applies to jpg output)")
	fs.Parse(args)

	if fs.NArg() < 2 {
		return errors.New("usage: mtool image [options] <input> <output>")
	}

	return imgconv.Run(
		imgconv.WithFormat(*format),
		imgconv.WithQuality(*quality),
		imgconv.WithInputPath(fs.Arg(0)),
		imgconv.WithOutputPath(fs.Arg(1)),
	)
}
