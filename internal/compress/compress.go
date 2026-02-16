package compress

import (
	"compress/bzip2"
	"compress/gzip"
	"compress/lzw"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
)

// Config holds configuration for the compress command.
type Config struct {
	Decompress  bool
	Format      string
	Level       int
	LZWLitWidth int
	InputPath   string
	OutputPath  string
}

// Option configures a Config.
type Option func(*Config)

func WithDecompress(d bool) Option     { return func(c *Config) { c.Decompress = d } }
func WithFormat(format string) Option  { return func(c *Config) { c.Format = format } }
func WithLevel(level int) Option       { return func(c *Config) { c.Level = level } }
func WithLZWLitWidth(w int) Option     { return func(c *Config) { c.LZWLitWidth = w } }
func WithInputPath(p string) Option    { return func(c *Config) { c.InputPath = p } }
func WithOutputPath(p string) Option   { return func(c *Config) { c.OutputPath = p } }

// Run compresses or decompresses data.
func Run(opts ...Option) error {
	cfg := &Config{Format: "gzip", Level: gzip.DefaultCompression, LZWLitWidth: 8}
	for _, o := range opts {
		o(cfg)
	}

	if cfg.InputPath == "" || cfg.OutputPath == "" {
		return errors.New("usage: mtool compress [-d] [-format gzip|zlib|lzw|bzip2] <input> <output>\n  note: bzip2 supports decompression only")
	}

	if cfg.Format == "lzw" && !cfg.Decompress {
		if cfg.LZWLitWidth < 2 || cfg.LZWLitWidth > 8 {
			return fmt.Errorf("litwidth must be between 2 and 8, got %d", cfg.LZWLitWidth)
		}
	}

	inFile, err := os.Open(cfg.InputPath)
	if err != nil {
		return fmt.Errorf("opening input: %w", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(cfg.OutputPath)
	if err != nil {
		return fmt.Errorf("creating output: %w", err)
	}
	defer outFile.Close()

	if cfg.Decompress {
		return DecompressStream(inFile, outFile, cfg.Format)
	}
	return CompressStream(inFile, outFile, cfg.Format, cfg.Level, cfg.LZWLitWidth)
}

// CompressStream compresses data from r to w.
func CompressStream(r io.Reader, w io.Writer, format string, level int, lzwLitWidth int) error {
	var compressor io.WriteCloser
	var err error

	switch format {
	case "gzip":
		compressor, err = gzip.NewWriterLevel(w, level)
	case "zlib":
		compressor, err = zlib.NewWriterLevel(w, level)
	case "lzw":
		if _, err := w.Write([]byte{byte(lzwLitWidth)}); err != nil {
			return fmt.Errorf("writing lzw header: %w", err)
		}
		compressor = lzw.NewWriter(w, lzw.LSB, lzwLitWidth)
	case "bzip2":
		return fmt.Errorf("bzip2 compression is not supported (decompress only)")
	default:
		return fmt.Errorf("unsupported format: %s (choices: gzip, zlib, lzw)", format)
	}
	if err != nil {
		return fmt.Errorf("creating compressor: %w", err)
	}

	n, err := io.Copy(compressor, r)
	if err != nil {
		return fmt.Errorf("compressing: %w", err)
	}
	if err := compressor.Close(); err != nil {
		return fmt.Errorf("finalizing: %w", err)
	}

	slog.Info("compressed", "format", format, "bytes_read", n)
	return nil
}

// DecompressStream decompresses data from r to w.
func DecompressStream(r io.Reader, w io.Writer, format string) error {
	var decompressor io.ReadCloser
	var err error

	switch format {
	case "gzip":
		decompressor, err = gzip.NewReader(r)
	case "zlib":
		decompressor, err = zlib.NewReader(r)
	case "lzw":
		var hdr [1]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return fmt.Errorf("reading lzw header: %w", err)
		}
		litWidth := int(hdr[0])
		if litWidth < 2 || litWidth > 8 {
			return fmt.Errorf("invalid lzw litwidth in header: %d", litWidth)
		}
		decompressor = lzw.NewReader(r, lzw.LSB, litWidth)
	case "bzip2":
		decompressor = io.NopCloser(bzip2.NewReader(r))
	default:
		return fmt.Errorf("unsupported format: %s (choices: gzip, zlib, lzw, bzip2)", format)
	}
	if err != nil {
		return fmt.Errorf("creating decompressor: %w", err)
	}
	defer decompressor.Close()

	n, err := io.Copy(w, decompressor)
	if err != nil {
		return fmt.Errorf("decompressing: %w", err)
	}

	slog.Info("decompressed", "format", format, "bytes_written", n)
	return nil
}
