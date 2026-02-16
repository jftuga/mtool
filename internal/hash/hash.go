package hash

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	gohash "hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
	"io"
	"os"
)

// Config holds configuration for the hash command.
type Config struct {
	Algorithm string
	HMACKey   string
	Files     []string
	Stdout    io.Writer
}

// Option configures a Config.
type Option func(*Config)

func WithAlgorithm(algo string) Option { return func(c *Config) { c.Algorithm = algo } }
func WithHMACKey(key string) Option    { return func(c *Config) { c.HMACKey = key } }
func WithFiles(files []string) Option  { return func(c *Config) { c.Files = files } }
func WithStdout(w io.Writer) Option    { return func(c *Config) { c.Stdout = w } }

// Run computes hashes of files or stdin.
func Run(opts ...Option) error {
	cfg := &Config{Algorithm: "sha256", Stdout: os.Stdout}
	for _, o := range opts {
		o(cfg)
	}

	if len(cfg.Files) == 0 {
		cfg.Files = []string{"-"}
	}

	nonHMACAlgos := map[string]bool{
		"crc32": true, "crc64": true, "adler32": true,
		"fnv32": true, "fnv64": true, "fnv128": true,
	}

	hashFuncs := map[string]func() gohash.Hash{
		"md5":      md5.New,
		"sha1":     sha1.New,
		"sha256":   sha256.New,
		"sha512":   sha512.New,
		"sha3-256": func() gohash.Hash { return sha3.New256() },
		"sha3-512": func() gohash.Hash { return sha3.New512() },
		"crc32":    func() gohash.Hash { return crc32.NewIEEE() },
		"crc64":    func() gohash.Hash { return crc64.New(crc64.MakeTable(crc64.ECMA)) },
		"adler32":  func() gohash.Hash { return adler32.New() },
		"fnv32":    func() gohash.Hash { return fnv.New32a() },
		"fnv64":    func() gohash.Hash { return fnv.New64a() },
		"fnv128":   func() gohash.Hash { return fnv.New128a() },
	}

	newHash, ok := hashFuncs[cfg.Algorithm]
	if !ok {
		return fmt.Errorf("unknown algorithm: %s (choices: md5, sha1, sha256, sha512, sha3-256, sha3-512, crc32, crc64, adler32, fnv32, fnv64, fnv128)", cfg.Algorithm)
	}

	for _, file := range cfg.Files {
		var h gohash.Hash
		if cfg.HMACKey != "" && !nonHMACAlgos[cfg.Algorithm] {
			h = hmac.New(newHash, []byte(cfg.HMACKey))
		} else {
			h = newHash()
		}

		var r io.Reader
		if file == "-" {
			r = os.Stdin
		} else {
			f, err := os.Open(file)
			if err != nil {
				return fmt.Errorf("opening %s: %w", file, err)
			}
			r = f
		}

		_, copyErr := io.Copy(h, r)
		if f, ok := r.(*os.File); ok && f != os.Stdin {
			f.Close()
		}
		if copyErr != nil {
			return fmt.Errorf("hashing %s: %w", file, copyErr)
		}

		name := file
		if file == "-" {
			name = "(stdin)"
		}
		fmt.Fprintf(cfg.Stdout, "%s  %s\n", hex.EncodeToString(h.Sum(nil)), name)
	}
	return nil
}
