package imgconv

import (
	"errors"
	"fmt"
	"image"
	"image/color/palette"
	"image/draw"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"log/slog"
	"mtool/internal/shared"
	"os"
	"path/filepath"
	"strings"
)

// SupportedImageFormats lists the formats available for encoding.
var SupportedImageFormats = map[string]bool{
	"png":  true,
	"jpg":  true,
	"jpeg": true,
	"gif":  true,
}

// Config holds configuration for the image conversion command.
type Config struct {
	Format     string
	Quality    int
	InputPath  string
	OutputPath string
}

// Option configures a Config.
type Option func(*Config)

func WithFormat(format string) Option      { return func(c *Config) { c.Format = format } }
func WithQuality(quality int) Option       { return func(c *Config) { c.Quality = quality } }
func WithInputPath(path string) Option     { return func(c *Config) { c.InputPath = path } }
func WithOutputPath(path string) Option    { return func(c *Config) { c.OutputPath = path } }

// Run converts images between formats.
func Run(opts ...Option) error {
	cfg := &Config{Quality: 90}
	for _, o := range opts {
		o(cfg)
	}

	if cfg.InputPath == "" || cfg.OutputPath == "" {
		return errors.New("usage: mtool image [options] <input> <output>")
	}

	outFmt := cfg.Format
	if outFmt == "" {
		outFmt = InferImageFormat(cfg.OutputPath)
		if outFmt == "" {
			return fmt.Errorf("cannot infer output format from %q — use -format flag", cfg.OutputPath)
		}
	}
	outFmt = strings.ToLower(outFmt)
	if outFmt == "jpeg" {
		outFmt = "jpg"
	}
	if !SupportedImageFormats[outFmt] {
		return fmt.Errorf("unsupported output format %q (choices: png, jpg, gif)", outFmt)
	}

	inFile, err := os.Open(cfg.InputPath)
	if err != nil {
		return fmt.Errorf("opening input: %w", err)
	}
	defer inFile.Close()

	img, inFmt, err := image.Decode(inFile)
	if err != nil {
		return fmt.Errorf("decoding %s: %w", cfg.InputPath, err)
	}
	slog.Info("decoded image", "format", inFmt,
		"width", img.Bounds().Dx(), "height", img.Bounds().Dy())

	outFile, err := os.Create(cfg.OutputPath)
	if err != nil {
		return fmt.Errorf("creating output: %w", err)
	}
	defer outFile.Close()

	if err := EncodeImage(outFile, img, outFmt, cfg.Quality); err != nil {
		os.Remove(cfg.OutputPath)
		return err
	}

	stat, _ := outFile.Stat()
	size := int64(0)
	if stat != nil {
		size = stat.Size()
	}
	slog.Info("encoded image", "format", outFmt, "output", cfg.OutputPath, "size", shared.FormatSize(size))
	return nil
}

// InferImageFormat returns a normalized format string based on the file extension.
func InferImageFormat(path string) string {
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(path)), ".")
	switch ext {
	case "png":
		return "png"
	case "jpg", "jpeg":
		return "jpg"
	case "gif":
		return "gif"
	default:
		return ""
	}
}

// EncodeImage writes img to w in the specified format.
func EncodeImage(w io.Writer, img image.Image, format string, quality int) error {
	switch format {
	case "png":
		return png.Encode(w, img)
	case "jpg":
		return jpeg.Encode(w, img, &jpeg.Options{Quality: quality})
	case "gif":
		return EncodeGIF(w, img)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// EncodeGIF quantizes the image to the Plan9 palette using Floyd-Steinberg dithering.
func EncodeGIF(w io.Writer, img image.Image) error {
	bounds := img.Bounds()
	palettedImg := image.NewPaletted(bounds, palette.Plan9)
	draw.FloydSteinberg.Draw(palettedImg, bounds, img, bounds.Min)
	return gif.Encode(w, palettedImg, nil)
}
