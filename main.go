// mtool is a Swiss army knife CLI utility that provides subcommands for file
// serving, HTTP fetching, file hashing, encoding/decoding, archiving, system
// information, password generation, HTTP benchmarking, TLS/DNS inspection,
// text transformation, image conversion, file encryption/decryption, and
// compression/decompression. It exclusively uses Go standard library packages.

package main

import (
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"
)

const pgmName = "mtool"
const pgmVersion = "2.0.0"
const pgmUrl = "https://github.com/jftuga/mtool"
const pgmDisclaimer = "DISCLAIMER: This program is vibe-coded. Use at your own risk."

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	commands := map[string]func([]string) error{
		"serve":     cmdServe,
		"fetch":     cmdFetch,
		"hash":      cmdHash,
		"encode":    cmdEncode,
		"decode":    cmdDecode,
		"info":      cmdInfo,
		"archive":   cmdArchive,
		"generate":  cmdGenerate,
		"bench":     cmdBench,
		"inspect":   cmdInspect,
		"transform": cmdTransform,
		"image":     cmdImage,
		"encrypt":   cmdEncrypt,
		"decrypt":   cmdDecrypt,
		"compress":  cmdCompress,
		"time":      cmdTime,
		"json":      cmdJSON,
		"net":       cmdNet,
		"jwt":       cmdJWT,
	}

	fn, ok := commands[cmd]
	if !ok {
		if cmd == "version" {
			bi, _ := debug.ReadBuildInfo()
			goVer := "unknown"
			if bi != nil {
				goVer = bi.GoVersion
			}
			fmt.Printf("mtool v%s (built with %s)\n", pgmVersion, goVer)
			fmt.Printf("%s\n\n%s\n", pgmUrl, pgmDisclaimer)
			return
		}
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}

	if err := fn(args); err != nil {
		slog.Error("command failed", "command", cmd, "error", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `mtool v%s — a Swiss army knife CLI utility

Usage: mtool <command> [options]

Commands:
  serve      Start an HTTP/HTTPS file server with directory listing
  fetch      Fetch a URL and display response details
  hash       Compute hashes of files or stdin
  encode     Encode data (base64, base32, hex, ascii85, url, qp, utf16)
  decode     Decode data (base64, base32, hex, ascii85, url, qp, utf16)
  info       Display system and network information
  archive    Create tar.gz or zip archives
  generate   Generate passwords, tokens, or random data
  bench      Benchmark an HTTP endpoint
  inspect    Inspect TLS certificates or DNS records
  transform  Transform text (upper, lower, regex, count)
  image      Convert images between PNG, JPEG, and GIF formats
  encrypt    Encrypt a file with AES-256-GCM (password-based)
  decrypt    Decrypt a file encrypted with the encrypt command
  compress   Compress or decompress data (gzip, zlib, lzw, bzip2)
  time       Convert timestamps (now, toepoch, fromepoch, convert)
  json       Process JSON (pretty, compact, validate, query)
  net        Network utilities (check, scan, wait, echo)
  jwt        Decode JWT tokens (no verification)
  version    Show version information

Run 'mtool <command> -h' for help on a specific command.
`, pgmVersion)
}
