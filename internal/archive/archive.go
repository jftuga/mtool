package archive

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Config holds configuration for the archive command.
type Config struct {
	Format  string
	Output  string
	Extract bool
	Files   []string
}

// Option configures a Config.
type Option func(*Config)

func WithFormat(format string) Option  { return func(c *Config) { c.Format = format } }
func WithOutput(output string) Option  { return func(c *Config) { c.Output = output } }
func WithExtract(extract bool) Option  { return func(c *Config) { c.Extract = extract } }
func WithFiles(files []string) Option  { return func(c *Config) { c.Files = files } }

// Run creates or extracts archives.
func Run(opts ...Option) error {
	cfg := &Config{Format: "tar.gz"}
	for _, o := range opts {
		o(cfg)
	}

	if cfg.Extract {
		if len(cfg.Files) == 0 {
			return errors.New("usage: mtool archive -extract <archive>")
		}
		dest := cfg.Output
		if dest == "" {
			dest = "."
		}
		return ExtractArchive(cfg.Files[0], dest)
	}

	if len(cfg.Files) == 0 {
		return errors.New("usage: mtool archive [options] <files...>")
	}

	if cfg.Output == "" {
		base := filepath.Base(cfg.Files[0])
		if len(cfg.Files) > 1 {
			base = "archive"
		}
		switch cfg.Format {
		case "tar.gz":
			cfg.Output = base + ".tar.gz"
		case "tar.zlib":
			cfg.Output = base + ".tar.zlib"
		case "zip":
			cfg.Output = base + ".zip"
		default:
			return fmt.Errorf("unknown format: %s", cfg.Format)
		}
	}

	switch cfg.Format {
	case "tar.gz":
		return CreateTarGz(cfg.Output, cfg.Files)
	case "tar.zlib":
		return CreateTarZlib(cfg.Output, cfg.Files)
	case "zip":
		return CreateZip(cfg.Output, cfg.Files)
	default:
		return fmt.Errorf("unknown format: %s", cfg.Format)
	}
}

// CreateTarGz creates a gzip-compressed tar archive.
func CreateTarGz(output string, files []string) error {
	f, err := os.Create(output)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	for _, file := range files {
		err := filepath.Walk(file, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			header, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			header.Name = p
			if err := tw.WriteHeader(header); err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			src, err := os.Open(p)
			if err != nil {
				return err
			}
			defer src.Close()
			_, err = io.Copy(tw, src)
			return err
		})
		if err != nil {
			return fmt.Errorf("archiving %s: %w", file, err)
		}
	}

	fmt.Fprintf(os.Stderr, "created %s\n", output)
	return nil
}

// CreateZip creates a ZIP archive.
func CreateZip(output string, files []string) error {
	f, err := os.Create(output)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	for _, file := range files {
		err := filepath.Walk(file, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			header, err := zip.FileInfoHeader(info)
			if err != nil {
				return err
			}
			header.Name = p
			header.Method = zip.Deflate

			w, err := zw.CreateHeader(header)
			if err != nil {
				return err
			}
			src, err := os.Open(p)
			if err != nil {
				return err
			}
			defer src.Close()
			_, err = io.Copy(w, src)
			return err
		})
		if err != nil {
			return fmt.Errorf("archiving %s: %w", file, err)
		}
	}

	fmt.Fprintf(os.Stderr, "created %s\n", output)
	return nil
}

// CreateTarZlib creates a zlib-compressed tar archive.
func CreateTarZlib(output string, files []string) error {
	f, err := os.Create(output)
	if err != nil {
		return err
	}
	defer f.Close()

	zw := zlib.NewWriter(f)
	defer zw.Close()

	tw := tar.NewWriter(zw)
	defer tw.Close()

	for _, file := range files {
		err := filepath.Walk(file, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			header, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			header.Name = p
			if err := tw.WriteHeader(header); err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			src, err := os.Open(p)
			if err != nil {
				return err
			}
			defer src.Close()
			_, err = io.Copy(tw, src)
			return err
		})
		if err != nil {
			return fmt.Errorf("archiving %s: %w", file, err)
		}
	}

	fmt.Fprintf(os.Stderr, "created %s\n", output)
	return nil
}

// ExtractArchive extracts an archive based on its extension.
func ExtractArchive(archivePath, dest string) error {
	ext := strings.ToLower(archivePath)
	switch {
	case strings.HasSuffix(ext, ".tar.gz") || strings.HasSuffix(ext, ".tgz"):
		return extractTarStream(archivePath, dest, func(r io.Reader) (io.ReadCloser, error) {
			return gzip.NewReader(r)
		})
	case strings.HasSuffix(ext, ".tar.zlib"):
		return extractTarStream(archivePath, dest, func(r io.Reader) (io.ReadCloser, error) {
			return zlib.NewReader(r)
		})
	case strings.HasSuffix(ext, ".zip"):
		return extractZip(archivePath, dest)
	default:
		return fmt.Errorf("cannot determine archive format from extension: %s", archivePath)
	}
}

func extractTarStream(archivePath, dest string, decompressor func(io.Reader) (io.ReadCloser, error)) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("opening archive: %w", err)
	}
	defer f.Close()

	dr, err := decompressor(f)
	if err != nil {
		return fmt.Errorf("creating decompressor: %w", err)
	}
	defer dr.Close()

	tr := tar.NewReader(dr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}

		target := filepath.Join(dest, filepath.Clean(header.Name))
		if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal path in archive: %s", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeSymlink, tar.TypeLink:
			slog.Warn("skipping link in archive", "name", header.Name, "type", header.Typeflag)
			continue
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		}
	}
	return nil
}

func extractZip(archivePath, dest string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("opening zip: %w", err)
	}
	defer zr.Close()

	for _, file := range zr.File {
		target := filepath.Join(dest, filepath.Clean(file.Name))
		if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal path in archive: %s", file.Name)
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := file.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(target)
		if err != nil {
			rc.Close()
			return err
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			rc.Close()
			return err
		}
		out.Close()
		rc.Close()
	}
	return nil
}
