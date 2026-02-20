package main

import (
	"errors"
	"flag"
	"github.com/jftuga/mtool/internal/crypt"
)

func cmdEncrypt(args []string) error {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	password := fs.String("password", "", "encryption password (or set MTOOL_PASSWORD env var)")
	fs.Parse(args)

	if fs.NArg() < 2 {
		return errors.New("usage: mtool encrypt -password <pass> <input> <output>")
	}

	return crypt.RunEncrypt(
		crypt.WithPassword(*password),
		crypt.WithInputPath(fs.Arg(0)),
		crypt.WithOutputPath(fs.Arg(1)),
	)
}

func cmdDecrypt(args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	password := fs.String("password", "", "decryption password (or set MTOOL_PASSWORD env var)")
	fs.Parse(args)

	if fs.NArg() < 2 {
		return errors.New("usage: mtool decrypt -password <pass> <input> <output>")
	}

	return crypt.RunDecrypt(
		crypt.WithPassword(*password),
		crypt.WithInputPath(fs.Arg(0)),
		crypt.WithOutputPath(fs.Arg(1)),
	)
}
