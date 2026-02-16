package main

import (
	"flag"
	"mtool/internal/hash"
)

func cmdHash(args []string) error {
	fs := flag.NewFlagSet("hash", flag.ExitOnError)
	algo := fs.String("algo", "sha256", "algorithm: md5, sha1, sha256, sha512, sha3-256, sha3-512, crc32, crc64, adler32, fnv32, fnv64, fnv128")
	hmacKey := fs.String("hmac", "", "HMAC key (uses HMAC mode with chosen algo)")
	fs.Parse(args)

	files := fs.Args()
	if len(files) == 0 {
		files = []string{"-"}
	}

	return hash.Run(
		hash.WithAlgorithm(*algo),
		hash.WithHMACKey(*hmacKey),
		hash.WithFiles(files),
	)
}
