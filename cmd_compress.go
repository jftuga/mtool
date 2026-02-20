package main

import (
	"compress/gzip"
	"errors"
	"flag"
	"github.com/jftuga/mtool/v2/internal/compress"
)

func cmdCompress(args []string) error {
	fs := flag.NewFlagSet("compress", flag.ExitOnError)
	decompress := fs.Bool("d", false, "decompress instead of compress")
	format := fs.String("format", "gzip", "compression format: gzip, zlib, lzw, bzip2 (bzip2: decompress only)")
	level := fs.Int("level", gzip.DefaultCompression, "compression level (1-9, not applicable to lzw/bzip2)")
	lzwLitWidth := fs.Int("litwidth", 8, "LZW literal code bit width (2-8, lzw format only)")
	fs.Parse(args)

	if fs.NArg() < 2 {
		return errors.New("usage: mtool compress [-d] [-format gzip|zlib|lzw|bzip2] <input> <output>\n  note: bzip2 supports decompression only")
	}

	return compress.Run(
		compress.WithDecompress(*decompress),
		compress.WithFormat(*format),
		compress.WithLevel(*level),
		compress.WithLZWLitWidth(*lzwLitWidth),
		compress.WithInputPath(fs.Arg(0)),
		compress.WithOutputPath(fs.Arg(1)),
	)
}
