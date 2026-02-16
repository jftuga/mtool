package main

import (
	"flag"
	"mtool/internal/codec"
	"mtool/internal/shared"
)

func cmdEncode(args []string) error {
	fs := flag.NewFlagSet("encode", flag.ExitOnError)
	format := fs.String("format", "base64", "encoding format: base64, base32, hex, ascii85, url, html, qp (quoted-printable), utf16")
	fs.Parse(args)

	input, err := shared.ReadInput(fs.Args())
	if err != nil {
		return err
	}

	return codec.RunEncode(
		codec.WithFormat(*format),
		codec.WithInput(input),
	)
}

func cmdDecode(args []string) error {
	fs := flag.NewFlagSet("decode", flag.ExitOnError)
	format := fs.String("format", "base64", "decoding format: base64, base32, hex, ascii85, url, html, qp (quoted-printable), utf16")
	fs.Parse(args)

	input, err := shared.ReadInput(fs.Args())
	if err != nil {
		return err
	}

	return codec.RunDecode(
		codec.WithFormat(*format),
		codec.WithInput(input),
	)
}
