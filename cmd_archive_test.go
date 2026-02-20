package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"io"
	"github.com/jftuga/mtool/v2/internal/archive"
	"os"
	"path/filepath"
	"testing"
)

func keys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

func TestCreateTarGz(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "a.txt"), "alpha")
	writeTestFile(t, filepath.Join(dir, "b.txt"), "bravo")

	archivePath := filepath.Join(dir, "out.tar.gz")
	err := archive.CreateTarGz(archivePath, []string{
		filepath.Join(dir, "a.txt"),
		filepath.Join(dir, "b.txt"),
	})
	if err != nil {
		t.Fatalf("CreateTarGz: %v", err)
	}

	f, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	found := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(tr)
		found[hdr.Name] = string(body)
	}

	// Verify entries use relative names (just the filename, no absolute path)
	if got, ok := found["a.txt"]; !ok || got != "alpha" {
		t.Errorf("a.txt: got %q, want %q (keys: %v)", got, "alpha", keys(found))
	}
	if got, ok := found["b.txt"]; !ok || got != "bravo" {
		t.Errorf("b.txt: got %q, want %q (keys: %v)", got, "bravo", keys(found))
	}
}

func TestCreateTarGzRelativePaths(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "a.txt"), "alpha")

	archivePath := filepath.Join(dir, "out.tar.gz")
	if err := archive.CreateTarGz(archivePath, []string{filepath.Join(dir, "a.txt")}); err != nil {
		t.Fatal(err)
	}

	f, _ := os.Open(archivePath)
	defer f.Close()
	gr, _ := gzip.NewReader(f)
	defer gr.Close()
	tr := tar.NewReader(gr)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.IsAbs(hdr.Name) {
		t.Errorf("archive entry should be relative, got %q", hdr.Name)
	}
	if hdr.Name != "a.txt" {
		t.Errorf("expected entry name %q, got %q", "a.txt", hdr.Name)
	}
}

func TestCreateZip(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "x.txt"), "xray")
	writeTestFile(t, filepath.Join(dir, "y.txt"), "yankee")

	archivePath := filepath.Join(dir, "out.zip")
	err := archive.CreateZip(archivePath, []string{
		filepath.Join(dir, "x.txt"),
		filepath.Join(dir, "y.txt"),
	})
	if err != nil {
		t.Fatalf("CreateZip: %v", err)
	}

	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()

	found := map[string]string{}
	for _, zf := range zr.File {
		rc, err := zf.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(rc)
		rc.Close()
		found[zf.Name] = string(body)
	}

	// Verify entries use relative names (just the filename, no absolute path)
	if got, ok := found["x.txt"]; !ok || got != "xray" {
		t.Errorf("x.txt: got %q, want %q (keys: %v)", got, "xray", keys(found))
	}
	if got, ok := found["y.txt"]; !ok || got != "yankee" {
		t.Errorf("y.txt: got %q, want %q (keys: %v)", got, "yankee", keys(found))
	}
}

func TestCreateTarGzDirectory(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "project")
	os.MkdirAll(filepath.Join(subdir, "sub"), 0o755)
	writeTestFile(t, filepath.Join(subdir, "root.txt"), "root content")
	writeTestFile(t, filepath.Join(subdir, "sub", "nested.txt"), "nested content")

	archivePath := filepath.Join(dir, "project.tar.gz")
	if err := archive.CreateTarGz(archivePath, []string{subdir}); err != nil {
		t.Fatalf("CreateTarGz directory: %v", err)
	}

	f, _ := os.Open(archivePath)
	defer f.Close()
	gr, _ := gzip.NewReader(f)
	defer gr.Close()

	tr := tar.NewReader(gr)
	names := []string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
	}

	if len(names) < 3 {
		t.Errorf("expected at least 3 entries (dir + 2 files), got %d: %v", len(names), names)
	}
	// Verify all entry names are relative (no absolute paths)
	for _, name := range names {
		if filepath.IsAbs(name) {
			t.Errorf("archive entry should be relative, got %q", name)
		}
	}
	// Verify the directory structure uses the walk root name
	expectedNames := map[string]bool{
		"project":              true,
		"project/root.txt":     true,
		"project/sub":          true,
		"project/sub/nested.txt": true,
	}
	for _, name := range names {
		if !expectedNames[name] {
			t.Errorf("unexpected archive entry: %q", name)
		}
	}
}

func TestArchiveExtractTarGz(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	os.MkdirAll(srcDir, 0o755)
	writeTestFile(t, filepath.Join(srcDir, "a.txt"), "alpha content")
	writeTestFile(t, filepath.Join(srcDir, "b.txt"), "bravo content")

	archivePath := filepath.Join(dir, "test.tar.gz")
	if err := archive.CreateTarGz(archivePath, []string{
		filepath.Join(srcDir, "a.txt"),
		filepath.Join(srcDir, "b.txt"),
	}); err != nil {
		t.Fatalf("CreateTarGz: %v", err)
	}

	destDir := filepath.Join(dir, "dest")
	os.MkdirAll(destDir, 0o755)

	if err := archive.ExtractArchive(archivePath, destDir); err != nil {
		t.Fatalf("ExtractArchive: %v", err)
	}

	for _, name := range []string{"a.txt", "b.txt"} {
		extractedPath := filepath.Join(destDir, name)
		data, err := os.ReadFile(extractedPath)
		if err != nil {
			t.Errorf("reading extracted %s: %v", name, err)
			continue
		}
		expected := map[string]string{"a.txt": "alpha content", "b.txt": "bravo content"}
		if string(data) != expected[name] {
			t.Errorf("%s: got %q, want %q", name, string(data), expected[name])
		}
	}
}

func TestArchiveExtractZip(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	os.MkdirAll(srcDir, 0o755)
	writeTestFile(t, filepath.Join(srcDir, "x.txt"), "xray content")
	writeTestFile(t, filepath.Join(srcDir, "y.txt"), "yankee content")

	archivePath := filepath.Join(dir, "test.zip")
	if err := archive.CreateZip(archivePath, []string{
		filepath.Join(srcDir, "x.txt"),
		filepath.Join(srcDir, "y.txt"),
	}); err != nil {
		t.Fatalf("CreateZip: %v", err)
	}

	destDir := filepath.Join(dir, "dest")
	os.MkdirAll(destDir, 0o755)

	if err := archive.ExtractArchive(archivePath, destDir); err != nil {
		t.Fatalf("ExtractArchive: %v", err)
	}

	for _, name := range []string{"x.txt", "y.txt"} {
		extractedPath := filepath.Join(destDir, name)
		data, err := os.ReadFile(extractedPath)
		if err != nil {
			t.Errorf("reading extracted %s: %v", name, err)
			continue
		}
		expected := map[string]string{"x.txt": "xray content", "y.txt": "yankee content"}
		if string(data) != expected[name] {
			t.Errorf("%s: got %q, want %q", name, string(data), expected[name])
		}
	}
}

func TestCreateTarZlib(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "a.txt"), "alpha")
	writeTestFile(t, filepath.Join(dir, "b.txt"), "bravo")

	archivePath := filepath.Join(dir, "out.tar.zlib")
	if err := archive.CreateTarZlib(archivePath, []string{
		filepath.Join(dir, "a.txt"),
		filepath.Join(dir, "b.txt"),
	}); err != nil {
		t.Fatalf("CreateTarZlib: %v", err)
	}

	destDir := filepath.Join(dir, "dest")
	os.MkdirAll(destDir, 0o755)

	if err := archive.ExtractArchive(archivePath, destDir); err != nil {
		t.Fatalf("ExtractArchive tar.zlib: %v", err)
	}

	for _, tc := range []struct{ name, want string }{
		{"a.txt", "alpha"},
		{"b.txt", "bravo"},
	} {
		var found bool
		filepath.Walk(destDir, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if filepath.Base(p) == tc.name {
				data, _ := os.ReadFile(p)
				if string(data) != tc.want {
					t.Errorf("%s: got %q, want %q", tc.name, string(data), tc.want)
				}
				found = true
			}
			return nil
		})
		if !found {
			t.Errorf("extracted file %s not found", tc.name)
		}
	}
}
