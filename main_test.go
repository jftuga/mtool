package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode"
)

// captureStdout redirects os.Stdout to a pipe, runs fn, then returns whatever
// was written. This is needed because many mtool functions write directly to
// os.Stdout rather than accepting an io.Writer.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = old

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading captured output: %v", err)
	}
	return string(out)
}

// ---------------------------------------------------------------------------
// formatSize
// ---------------------------------------------------------------------------

func TestFormatSize(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
		{1099511627776, "1.0 TB"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.input), func(t *testing.T) {
			got := formatSize(tt.input)
			if got != tt.want {
				t.Errorf("formatSize(%d) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// tlsVersionString
// ---------------------------------------------------------------------------

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		input uint16
		want  string
	}{
		{0x0301, "1.0"},
		{0x0302, "1.1"},
		{0x0303, "1.2"},
		{0x0304, "1.3"},
		{0x9999, "9999"},
	}
	for _, tt := range tests {
		got := tlsVersionString(tt.input)
		if got != tt.want {
			t.Errorf("tlsVersionString(0x%04x) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// percentile
// ---------------------------------------------------------------------------

func TestPercentile(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if got := percentile(nil, 50); got != 0 {
			t.Errorf("percentile(nil, 50) = %f, want 0", got)
		}
	})

	t.Run("single element", func(t *testing.T) {
		if got := percentile([]float64{42.0}, 99); got != 42.0 {
			t.Errorf("percentile([42], 99) = %f, want 42", got)
		}
	})

	sorted := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	t.Run("p50", func(t *testing.T) {
		got := percentile(sorted, 50)
		if got != 5.0 {
			t.Errorf("p50 = %f, want 5", got)
		}
	})

	t.Run("p100", func(t *testing.T) {
		got := percentile(sorted, 100)
		if got != 10.0 {
			t.Errorf("p100 = %f, want 10", got)
		}
	})

	t.Run("p10", func(t *testing.T) {
		got := percentile(sorted, 10)
		if got != 1.0 {
			t.Errorf("p10 = %f, want 1", got)
		}
	})
}

// ---------------------------------------------------------------------------
// generatePassword
// ---------------------------------------------------------------------------

func TestGeneratePassword(t *testing.T) {
	t.Run("alpha only", func(t *testing.T) {
		pw, err := generatePassword(30, "alpha")
		if err != nil {
			t.Fatal(err)
		}
		if len(pw) != 30 {
			t.Errorf("length = %d, want 30", len(pw))
		}
		for _, r := range pw {
			if !unicode.IsLetter(r) {
				t.Errorf("non-letter rune %q in alpha password", r)
			}
		}
	})

	t.Run("alnum only", func(t *testing.T) {
		pw, err := generatePassword(30, "alnum")
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range pw {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
				t.Errorf("unexpected rune %q in alnum password", r)
			}
		}
	})

	t.Run("full charset has mixed categories", func(t *testing.T) {
		// Run multiple times to reduce flakiness from randomness.
		for range 10 {
			pw, err := generatePassword(20, "full")
			if err != nil {
				t.Fatal(err)
			}
			if len(pw) != 20 {
				t.Errorf("length = %d, want 20", len(pw))
			}
			hasLower, hasUpper, hasDigit, hasSpecial := false, false, false, false
			for _, r := range pw {
				switch {
				case unicode.IsLower(r):
					hasLower = true
				case unicode.IsUpper(r):
					hasUpper = true
				case unicode.IsDigit(r):
					hasDigit = true
				default:
					hasSpecial = true
				}
			}
			if hasLower && hasUpper && hasDigit && hasSpecial {
				return // pass — found one that has all categories
			}
		}
		t.Error("full charset password never contained all four categories in 10 attempts")
	})

	t.Run("respects length", func(t *testing.T) {
		for _, length := range []int{1, 4, 8, 50, 128} {
			pw, err := generatePassword(length, "alnum")
			if err != nil {
				t.Fatal(err)
			}
			if len(pw) != length {
				t.Errorf("generatePassword(%d, alnum): length = %d", length, len(pw))
			}
		}
	})
}

// ---------------------------------------------------------------------------
// generateToken
// ---------------------------------------------------------------------------

func TestGenerateToken(t *testing.T) {
	hexRe := regexp.MustCompile(`^[0-9a-f]+$`)

	for _, length := range []int{8, 16, 32, 64} {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			tok, err := generateToken(length)
			if err != nil {
				t.Fatal(err)
			}
			if len(tok) != length {
				t.Errorf("token length = %d, want %d", len(tok), length)
			}
			if !hexRe.MatchString(tok) {
				t.Errorf("token %q contains non-hex characters", tok)
			}
		})
	}

	t.Run("uniqueness", func(t *testing.T) {
		a, _ := generateToken(32)
		b, _ := generateToken(32)
		if a == b {
			t.Error("two generated tokens are identical")
		}
	})
}

// ---------------------------------------------------------------------------
// generateUUID
// ---------------------------------------------------------------------------

func TestGenerateUUID(t *testing.T) {
	uuidRe := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

	for range 20 {
		uuid, err := generateUUID()
		if err != nil {
			t.Fatal(err)
		}
		if !uuidRe.MatchString(uuid) {
			t.Errorf("UUID %q does not match v4 format", uuid)
		}
	}

	t.Run("uniqueness", func(t *testing.T) {
		a, _ := generateUUID()
		b, _ := generateUUID()
		if a == b {
			t.Error("two generated UUIDs are identical")
		}
	})
}

// ---------------------------------------------------------------------------
// generateBigInt
// ---------------------------------------------------------------------------

func TestGenerateBigInt(t *testing.T) {
	for _, bits := range []int{8, 64, 128, 256} {
		t.Run(fmt.Sprintf("%d_bits", bits), func(t *testing.T) {
			s, err := generateBigInt(bits)
			if err != nil {
				t.Fatal(err)
			}
			if s == "" {
				t.Error("empty string returned")
			}
			// Every character should be a digit (it's a decimal string).
			for _, r := range s {
				if !unicode.IsDigit(r) {
					t.Errorf("non-digit rune %q in bigint output %q", r, s)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// sortLines
// ---------------------------------------------------------------------------

func TestSortLines(t *testing.T) {
	t.Run("alphabetical", func(t *testing.T) {
		input := "cherry\napple\nbanana\n"
		got := captureStdout(t, func() { sortLines(input, false, false, false, 0) })
		want := "apple\nbanana\ncherry\n"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("reverse alphabetical", func(t *testing.T) {
		input := "cherry\napple\nbanana\n"
		got := captureStdout(t, func() { sortLines(input, false, true, false, 0) })
		want := "cherry\nbanana\napple\n"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("numeric", func(t *testing.T) {
		input := "10\n2\n1\n20\n3\n"
		got := captureStdout(t, func() { sortLines(input, true, false, false, 0) })
		want := "1\n2\n3\n10\n20\n"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("numeric descending", func(t *testing.T) {
		input := "10\n2\n1\n20\n3\n"
		got := captureStdout(t, func() { sortLines(input, true, true, false, 0) })
		want := "20\n10\n3\n2\n1\n"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("case insensitive", func(t *testing.T) {
		input := "Banana\napple\nCherry\n"
		got := captureStdout(t, func() { sortLines(input, false, false, true, 0) })
		want := "apple\nBanana\nCherry\n"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("by field", func(t *testing.T) {
		input := "alice 30\nbob 20\ncharlie 25\n"
		got := captureStdout(t, func() { sortLines(input, true, false, false, 2) })
		want := "bob 20\ncharlie 25\nalice 30\n"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("field out of range sorts as empty", func(t *testing.T) {
		input := "one\ntwo\nthree\n"
		got := captureStdout(t, func() { sortLines(input, false, false, false, 5) })
		// All keys are "", so stable sort preserves original order.
		want := "one\ntwo\nthree\n"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("numeric with non-numeric lines", func(t *testing.T) {
		input := "5\nfoo\n1\nbar\n10\n"
		got := captureStdout(t, func() { sortLines(input, true, false, false, 0) })
		lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
		// Numeric lines should come before non-numeric.
		if lines[0] != "1" || lines[1] != "5" || lines[2] != "10" {
			t.Errorf("numeric lines not sorted first: %v", lines)
		}
	})
}

// ---------------------------------------------------------------------------
// printTextStats
// ---------------------------------------------------------------------------

func TestPrintTextStats(t *testing.T) {
	t.Run("basic counts", func(t *testing.T) {
		input := "Hello World 123\nFoo\n"
		got := captureStdout(t, func() { printTextStats(input) })

		assertContains(t, got, "Lines:", "2")
		assertContains(t, got, "Words:", "4")
		assertContains(t, got, "Letters:", "13")
		assertContains(t, got, "Digits:", "3")
	})

	t.Run("empty string", func(t *testing.T) {
		got := captureStdout(t, func() { printTextStats("") })
		assertContains(t, got, "Words:", "0")
		assertContains(t, got, "Bytes:", "0")
	})

	t.Run("no trailing newline still counts as a line", func(t *testing.T) {
		got := captureStdout(t, func() { printTextStats("hello") })
		assertContains(t, got, "Lines:", "1")
	})

	t.Run("unicode characters", func(t *testing.T) {
		// "Hej" in Swedish + emoji: each emoji is multiple bytes but one rune.
		input := "Hej!"
		got := captureStdout(t, func() { printTextStats(input) })
		assertContains(t, got, "Characters:", "4")
		assertContains(t, got, "Letters:", "3")
	})
}

// ---------------------------------------------------------------------------
// printWordFrequency
// ---------------------------------------------------------------------------

func TestPrintWordFrequency(t *testing.T) {
	t.Run("frequency ordering", func(t *testing.T) {
		input := "the cat sat on the mat the cat"
		got := captureStdout(t, func() { printWordFrequency(input) })

		lines := strings.Split(strings.TrimSpace(got), "\n")
		// First line is the header.
		if len(lines) < 2 {
			t.Fatalf("expected at least a header + 1 data line, got %d lines", len(lines))
		}
		if !strings.Contains(lines[0], "WORD") {
			t.Errorf("missing header, got: %q", lines[0])
		}
		// "the" appears 3 times, should be the first data line.
		if !strings.Contains(lines[1], "the") || !strings.Contains(lines[1], "3") {
			t.Errorf("expected 'the 3' first, got: %q", lines[1])
		}
	})

	t.Run("case insensitive", func(t *testing.T) {
		input := "Go go GO"
		got := captureStdout(t, func() { printWordFrequency(input) })
		if !strings.Contains(got, "3") {
			t.Errorf("expected 'go' counted 3 times, got: %s", got)
		}
	})
}

// ---------------------------------------------------------------------------
// archive: createTarGz
// ---------------------------------------------------------------------------

func TestCreateTarGz(t *testing.T) {
	dir := t.TempDir()

	// Create source files.
	writeTestFile(t, filepath.Join(dir, "a.txt"), "alpha")
	writeTestFile(t, filepath.Join(dir, "b.txt"), "bravo")

	archive := filepath.Join(dir, "out.tar.gz")
	err := createTarGz(archive, []string{
		filepath.Join(dir, "a.txt"),
		filepath.Join(dir, "b.txt"),
	})
	if err != nil {
		t.Fatalf("createTarGz: %v", err)
	}

	// Read back and verify contents.
	f, err := os.Open(archive)
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
		found[filepath.Base(hdr.Name)] = string(body)
	}

	if got, ok := found["a.txt"]; !ok || got != "alpha" {
		t.Errorf("a.txt: got %q, want %q", got, "alpha")
	}
	if got, ok := found["b.txt"]; !ok || got != "bravo" {
		t.Errorf("b.txt: got %q, want %q", got, "bravo")
	}
}

// ---------------------------------------------------------------------------
// archive: createZip
// ---------------------------------------------------------------------------

func TestCreateZip(t *testing.T) {
	dir := t.TempDir()

	writeTestFile(t, filepath.Join(dir, "x.txt"), "xray")
	writeTestFile(t, filepath.Join(dir, "y.txt"), "yankee")

	archive := filepath.Join(dir, "out.zip")
	err := createZip(archive, []string{
		filepath.Join(dir, "x.txt"),
		filepath.Join(dir, "y.txt"),
	})
	if err != nil {
		t.Fatalf("createZip: %v", err)
	}

	zr, err := zip.OpenReader(archive)
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
		found[filepath.Base(zf.Name)] = string(body)
	}

	if got, ok := found["x.txt"]; !ok || got != "xray" {
		t.Errorf("x.txt: got %q, want %q", got, "xray")
	}
	if got, ok := found["y.txt"]; !ok || got != "yankee" {
		t.Errorf("y.txt: got %q, want %q", got, "yankee")
	}
}

// ---------------------------------------------------------------------------
// archive: createTarGz with directory
// ---------------------------------------------------------------------------

func TestCreateTarGzDirectory(t *testing.T) {
	dir := t.TempDir()

	subdir := filepath.Join(dir, "project")
	os.MkdirAll(filepath.Join(subdir, "sub"), 0o755)
	writeTestFile(t, filepath.Join(subdir, "root.txt"), "root content")
	writeTestFile(t, filepath.Join(subdir, "sub", "nested.txt"), "nested content")

	archive := filepath.Join(dir, "project.tar.gz")
	if err := createTarGz(archive, []string{subdir}); err != nil {
		t.Fatalf("createTarGz directory: %v", err)
	}

	f, _ := os.Open(archive)
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
}

// ---------------------------------------------------------------------------
// loadDirectoryTemplate
// ---------------------------------------------------------------------------

func TestLoadDirectoryTemplate(t *testing.T) {
	tmpl, err := loadDirectoryTemplate()
	if err != nil {
		t.Fatalf("loadDirectoryTemplate: %v", err)
	}

	data := struct {
		Path    string
		Entries []dirEntry
	}{
		Path: "/test",
		Entries: []dirEntry{
			{Name: "file.txt", Link: "file.txt", Size: "1.0 KB", ModTime: "2025-01-01 00:00:00", IsDir: false},
			{Name: "subdir", Link: "subdir", Size: "-", ModTime: "2025-01-01 00:00:00", IsDir: true},
		},
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("template execute: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "/test") {
		t.Error("rendered HTML missing path")
	}
	if !strings.Contains(html, "file.txt") {
		t.Error("rendered HTML missing file entry")
	}
	if !strings.Contains(html, "subdir") {
		t.Error("rendered HTML missing directory entry")
	}
}

// ---------------------------------------------------------------------------
// generateSelfSignedCert
// ---------------------------------------------------------------------------

func TestGenerateSelfSignedCert(t *testing.T) {
	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}

	if len(tlsCert.Certificate) == 0 {
		t.Fatal("no certificate data in TLS certificate")
	}

	// Parse the leaf certificate.
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing leaf certificate: %v", err)
	}

	t.Run("subject", func(t *testing.T) {
		if leaf.Subject.CommonName != "localhost" {
			t.Errorf("CommonName = %q, want %q", leaf.Subject.CommonName, "localhost")
		}
	})

	t.Run("self-signed", func(t *testing.T) {
		if leaf.Issuer.CommonName != leaf.Subject.CommonName {
			t.Errorf("Issuer CN = %q, Subject CN = %q — expected self-signed", leaf.Issuer.CommonName, leaf.Subject.CommonName)
		}
	})

	t.Run("validity window", func(t *testing.T) {
		now := time.Now()
		if now.Before(leaf.NotBefore) {
			t.Errorf("certificate not yet valid (NotBefore: %s)", leaf.NotBefore)
		}
		if now.After(leaf.NotAfter) {
			t.Errorf("certificate already expired (NotAfter: %s)", leaf.NotAfter)
		}
		// Should expire in roughly 24 hours.
		remaining := time.Until(leaf.NotAfter)
		if remaining < 23*time.Hour || remaining > 25*time.Hour {
			t.Errorf("expected ~24h validity, got %s", remaining)
		}
	})

	t.Run("DNS names", func(t *testing.T) {
		found := false
		for _, name := range leaf.DNSNames {
			if name == "localhost" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DNS names %v missing 'localhost'", leaf.DNSNames)
		}
	})

	t.Run("IP addresses", func(t *testing.T) {
		hasLoopback := false
		for _, ip := range leaf.IPAddresses {
			if ip.Equal(net.IPv4(127, 0, 0, 1)) || ip.Equal(net.IPv6loopback) {
				hasLoopback = true
				break
			}
		}
		if !hasLoopback {
			t.Errorf("IP addresses %v missing loopback", leaf.IPAddresses)
		}
	})

	t.Run("usable by tls.Config", func(t *testing.T) {
		// Verify the cert+key pair works in a TLS config without error.
		cfg := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		}

		listener, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
		if err != nil {
			t.Fatalf("tls.Listen: %v", err)
		}
		listener.Close()
	})

	t.Run("uniqueness", func(t *testing.T) {
		// Two calls should produce different serial numbers.
		other, err := generateSelfSignedCert()
		if err != nil {
			t.Fatal(err)
		}
		otherLeaf, err := x509.ParseCertificate(other.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if leaf.SerialNumber.Cmp(otherLeaf.SerialNumber) == 0 {
			t.Error("two certs have identical serial numbers")
		}
	})
}

// ---------------------------------------------------------------------------
// inferImageFormat
// ---------------------------------------------------------------------------

func TestInferImageFormat(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"photo.png", "png"},
		{"photo.PNG", "png"},
		{"photo.jpg", "jpg"},
		{"photo.jpeg", "jpg"},
		{"photo.JPEG", "jpg"},
		{"photo.gif", "gif"},
		{"photo.bmp", ""},
		{"photo.tiff", ""},
		{"noext", ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := inferImageFormat(tt.path)
			if got != tt.want {
				t.Errorf("inferImageFormat(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// encodeImage
// ---------------------------------------------------------------------------

// newTestImage creates a small 4x4 RGBA image with known pixel values.
func newTestImage() *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	colors := []color.RGBA{
		{255, 0, 0, 255},
		{0, 255, 0, 255},
		{0, 0, 255, 255},
		{255, 255, 0, 255},
	}
	for y := range 4 {
		for x := range 4 {
			img.SetRGBA(x, y, colors[(x+y)%len(colors)])
		}
	}
	return img
}

func TestEncodeImage_PNG(t *testing.T) {
	img := newTestImage()
	var buf bytes.Buffer

	if err := encodeImage(&buf, img, "png", 0); err != nil {
		t.Fatalf("encodeImage png: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("png output is empty")
	}

	// Decode and verify dimensions.
	decoded, err := png.Decode(&buf)
	if err != nil {
		t.Fatalf("decoding png: %v", err)
	}
	if decoded.Bounds() != img.Bounds() {
		t.Errorf("bounds = %v, want %v", decoded.Bounds(), img.Bounds())
	}
}

func TestEncodeImage_JPEG(t *testing.T) {
	img := newTestImage()
	var buf bytes.Buffer

	if err := encodeImage(&buf, img, "jpg", 75); err != nil {
		t.Fatalf("encodeImage jpg: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("jpeg output is empty")
	}

	decoded, err := jpeg.Decode(&buf)
	if err != nil {
		t.Fatalf("decoding jpeg: %v", err)
	}
	if decoded.Bounds() != img.Bounds() {
		t.Errorf("bounds = %v, want %v", decoded.Bounds(), img.Bounds())
	}
}

func TestEncodeImage_GIF(t *testing.T) {
	img := newTestImage()
	var buf bytes.Buffer

	if err := encodeImage(&buf, img, "gif", 0); err != nil {
		t.Fatalf("encodeImage gif: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("gif output is empty")
	}

	decoded, err := gif.Decode(&buf)
	if err != nil {
		t.Fatalf("decoding gif: %v", err)
	}
	if decoded.Bounds() != img.Bounds() {
		t.Errorf("bounds = %v, want %v", decoded.Bounds(), img.Bounds())
	}
}

func TestEncodeImage_Unsupported(t *testing.T) {
	img := newTestImage()
	var buf bytes.Buffer

	if err := encodeImage(&buf, img, "bmp", 0); err == nil {
		t.Error("expected error for unsupported format, got nil")
	}
}

func TestImageRoundTrip(t *testing.T) {
	// PNG -> JPEG -> PNG round-trip via file system.
	dir := t.TempDir()
	src := newTestImage()

	// Write source PNG.
	pngPath := filepath.Join(dir, "source.png")
	f, err := os.Create(pngPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(f, src); err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Convert PNG -> JPEG using cmdImage.
	jpgPath := filepath.Join(dir, "output.jpg")
	if err := cmdImage([]string{"-quality", "95", pngPath, jpgPath}); err != nil {
		t.Fatalf("cmdImage png->jpg: %v", err)
	}

	stat, err := os.Stat(jpgPath)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Size() == 0 {
		t.Error("JPEG output file is empty")
	}

	// Convert JPEG -> GIF using cmdImage.
	gifPath := filepath.Join(dir, "output.gif")
	if err := cmdImage([]string{jpgPath, gifPath}); err != nil {
		t.Fatalf("cmdImage jpg->gif: %v", err)
	}

	stat, err = os.Stat(gifPath)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Size() == 0 {
		t.Error("GIF output file is empty")
	}

	// Convert GIF -> PNG using cmdImage with explicit -format.
	pngPath2 := filepath.Join(dir, "final.png")
	if err := cmdImage([]string{"-format", "png", gifPath, pngPath2}); err != nil {
		t.Fatalf("cmdImage gif->png: %v", err)
	}

	// Open final PNG, verify it decodes and has correct dimensions.
	final, err := os.Open(pngPath2)
	if err != nil {
		t.Fatal(err)
	}
	defer final.Close()

	decoded, _, err := image.Decode(final)
	if err != nil {
		t.Fatalf("decoding final png: %v", err)
	}
	if decoded.Bounds() != src.Bounds() {
		t.Errorf("final bounds = %v, want %v", decoded.Bounds(), src.Bounds())
	}
}

// ---------------------------------------------------------------------------
// deriveKey
// ---------------------------------------------------------------------------

func TestDeriveKey(t *testing.T) {
	mustDeriveKey := func(t *testing.T, password, salt []byte) []byte {
		t.Helper()
		key, err := deriveKey(password, salt)
		if err != nil {
			t.Fatalf("deriveKey: %v", err)
		}
		return key
	}

	t.Run("deterministic", func(t *testing.T) {
		salt := []byte("fixed-salt-value")
		key1 := mustDeriveKey(t, []byte("password"), salt)
		key2 := mustDeriveKey(t, []byte("password"), salt)
		if !bytes.Equal(key1, key2) {
			t.Error("same password+salt produced different keys")
		}
	})

	t.Run("correct length", func(t *testing.T) {
		key := mustDeriveKey(t, []byte("password"), []byte("salt"))
		if len(key) != 32 {
			t.Errorf("key length = %d, want 32", len(key))
		}
	})

	t.Run("different passwords differ", func(t *testing.T) {
		salt := []byte("same-salt")
		k1 := mustDeriveKey(t, []byte("password1"), salt)
		k2 := mustDeriveKey(t, []byte("password2"), salt)
		if bytes.Equal(k1, k2) {
			t.Error("different passwords produced identical keys")
		}
	})

	t.Run("different salts differ", func(t *testing.T) {
		k1 := mustDeriveKey(t, []byte("password"), []byte("salt-a"))
		k2 := mustDeriveKey(t, []byte("password"), []byte("salt-b"))
		if bytes.Equal(k1, k2) {
			t.Error("different salts produced identical keys")
		}
	})
}

// ---------------------------------------------------------------------------
// encrypt / decrypt round-trip
// ---------------------------------------------------------------------------

func TestEncryptDecryptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "secret.txt")
	encPath := filepath.Join(dir, "secret.enc")
	decPath := filepath.Join(dir, "secret.dec")
	password := "correct-horse-battery-staple"

	original := "This is sensitive data that must survive encryption.\n"
	writeTestFile(t, plainPath, original)

	// Encrypt.
	if err := cmdEncrypt([]string{"-password", password, plainPath, encPath}); err != nil {
		t.Fatalf("cmdEncrypt: %v", err)
	}

	// Encrypted file should exist and differ from plaintext.
	encData, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(encData) == original {
		t.Error("encrypted data is identical to plaintext")
	}
	// Must be larger than plaintext (salt + nonce + auth tag overhead).
	if len(encData) <= len(original) {
		t.Errorf("encrypted size (%d) should exceed plaintext size (%d)", len(encData), len(original))
	}

	// Decrypt.
	if err := cmdDecrypt([]string{"-password", password, encPath, decPath}); err != nil {
		t.Fatalf("cmdDecrypt: %v", err)
	}

	decData, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(decData) != original {
		t.Errorf("decrypted = %q, want %q", string(decData), original)
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "data.txt")
	encPath := filepath.Join(dir, "data.enc")
	decPath := filepath.Join(dir, "data.dec")

	writeTestFile(t, plainPath, "secret stuff")

	if err := cmdEncrypt([]string{"-password", "right", plainPath, encPath}); err != nil {
		t.Fatal(err)
	}

	err := cmdDecrypt([]string{"-password", "wrong", encPath, decPath})
	if err == nil {
		t.Error("expected error decrypting with wrong password, got nil")
	}
}

func TestEncryptProducesUniqueOutput(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "data.txt")
	enc1 := filepath.Join(dir, "out1.enc")
	enc2 := filepath.Join(dir, "out2.enc")

	writeTestFile(t, plainPath, "same input twice")

	if err := cmdEncrypt([]string{"-password", "pass", plainPath, enc1}); err != nil {
		t.Fatal(err)
	}
	if err := cmdEncrypt([]string{"-password", "pass", plainPath, enc2}); err != nil {
		t.Fatal(err)
	}

	d1, _ := os.ReadFile(enc1)
	d2, _ := os.ReadFile(enc2)
	if bytes.Equal(d1, d2) {
		t.Error("two encryptions of the same file produced identical output (salt/nonce should differ)")
	}
}

// ---------------------------------------------------------------------------
// compress / decompress round-trip
// ---------------------------------------------------------------------------

func TestCompressDecompressGzip(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	compPath := filepath.Join(dir, "input.txt.gz")
	decPath := filepath.Join(dir, "output.txt")

	original := strings.Repeat("the quick brown fox jumps over the lazy dog\n", 100)
	writeTestFile(t, srcPath, original)

	// Compress.
	if err := cmdCompress([]string{"-format", "gzip", srcPath, compPath}); err != nil {
		t.Fatalf("compress: %v", err)
	}

	compData, err := os.ReadFile(compPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(compData) >= len(original) {
		t.Errorf("compressed size (%d) should be less than original (%d)", len(compData), len(original))
	}

	// Decompress.
	if err := cmdCompress([]string{"-d", "-format", "gzip", compPath, decPath}); err != nil {
		t.Fatalf("decompress: %v", err)
	}

	decData, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(decData) != original {
		t.Error("decompressed data does not match original")
	}
}

func TestCompressDecompressZlib(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	compPath := filepath.Join(dir, "input.zlib")
	decPath := filepath.Join(dir, "output.txt")

	original := strings.Repeat("zlib compression test data\n", 50)
	writeTestFile(t, srcPath, original)

	if err := cmdCompress([]string{"-format", "zlib", srcPath, compPath}); err != nil {
		t.Fatalf("compress: %v", err)
	}

	compStat, _ := os.Stat(compPath)
	if compStat.Size() >= int64(len(original)) {
		t.Errorf("compressed size (%d) should be less than original (%d)", compStat.Size(), len(original))
	}

	if err := cmdCompress([]string{"-d", "-format", "zlib", compPath, decPath}); err != nil {
		t.Fatalf("decompress: %v", err)
	}

	decData, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(decData) != original {
		t.Error("decompressed data does not match original")
	}
}

func TestCompressDecompressBzip2(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	compPath := filepath.Join(dir, "input.txt.bz2")
	decPath := filepath.Join(dir, "output.txt")

	original := strings.Repeat("bzip2 decompression test data\n", 50)
	writeTestFile(t, srcPath, original)

	// Compress using the system bzip2 command (Go stdlib has no bzip2 writer).
	cmd := exec.Command("bzip2", "-k", srcPath)
	if err := cmd.Run(); err != nil {
		t.Skipf("bzip2 command not available: %v", err)
	}

	compStat, err := os.Stat(compPath)
	if err != nil {
		t.Fatalf("compressed file not created: %v", err)
	}
	if compStat.Size() >= int64(len(original)) {
		t.Errorf("compressed size (%d) should be less than original (%d)", compStat.Size(), len(original))
	}

	// Decompress using mtool.
	if err := cmdCompress([]string{"-d", "-format", "bzip2", compPath, decPath}); err != nil {
		t.Fatalf("decompress: %v", err)
	}

	decData, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(decData) != original {
		t.Error("decompressed data does not match original")
	}
}

func TestCompressBzip2RejectsCompress(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	compPath := filepath.Join(dir, "input.txt.bz2")

	writeTestFile(t, srcPath, "some data\n")

	err := cmdCompress([]string{"-format", "bzip2", srcPath, compPath})
	if err == nil {
		t.Fatal("expected error when compressing with bzip2, got nil")
	}
	if !strings.Contains(err.Error(), "decompress only") {
		t.Errorf("expected 'decompress only' in error, got: %v", err)
	}
}

func TestCompressDecompressLZW(t *testing.T) {
	// Test with different litwidths. Each litwidth N can encode byte values 0 to 2^N-1.
	// litwidth 7 handles 0-127 (ASCII text), litwidth 8 handles 0-255 (all bytes).
	// litwidth 6 handles 0-63, so we use data restricted to that range.
	tests := []struct {
		litwidth string
		data     string
	}{
		{"6", strings.Repeat("\x01\x02\x03\x10\x20\x3F", 100)}, // bytes 0-63 only
		{"7", strings.Repeat("LZW test 01234\n", 100)},         // ASCII 0-127
		{"8", strings.Repeat("lzw compression test data\n", 100)},
	}

	for _, tc := range tests {
		t.Run("litwidth_"+tc.litwidth, func(t *testing.T) {
			dir := t.TempDir()
			srcPath := filepath.Join(dir, "input.bin")
			compPath := filepath.Join(dir, "input.lzw")
			decPath := filepath.Join(dir, "output.bin")

			if err := os.WriteFile(srcPath, []byte(tc.data), 0o644); err != nil {
				t.Fatal(err)
			}

			// Compress with specific litwidth.
			if err := cmdCompress([]string{"-format", "lzw", "-litwidth", tc.litwidth, srcPath, compPath}); err != nil {
				t.Fatalf("compress: %v", err)
			}

			// Verify the first byte of the compressed file is the litwidth header.
			compData, err := os.ReadFile(compPath)
			if err != nil {
				t.Fatal(err)
			}
			if len(compData) == 0 {
				t.Fatal("compressed file is empty")
			}
			if fmt.Sprintf("%d", compData[0]) != tc.litwidth {
				t.Errorf("expected litwidth header byte %s, got %d", tc.litwidth, compData[0])
			}

			// Decompress without specifying litwidth — should auto-detect from header.
			if err := cmdCompress([]string{"-d", "-format", "lzw", compPath, decPath}); err != nil {
				t.Fatalf("decompress: %v", err)
			}

			decData, err := os.ReadFile(decPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(decData) != tc.data {
				t.Error("decompressed data does not match original")
			}
		})
	}
}

func TestHashAdler32(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	writeTestFile(t, srcPath, "hello")

	out := captureStdout(t, func() {
		if err := cmdHash([]string{"-algo", "adler32", srcPath}); err != nil {
			t.Fatalf("hash: %v", err)
		}
	})
	if !strings.Contains(out, "062c0215") {
		t.Errorf("expected adler32 hash 062c0215, got: %s", strings.TrimSpace(out))
	}
}

func TestHashCRC64(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	writeTestFile(t, srcPath, "hello")

	out := captureStdout(t, func() {
		if err := cmdHash([]string{"-algo", "crc64", srcPath}); err != nil {
			t.Fatalf("hash: %v", err)
		}
	})
	// Verify it produces a 16-hex-char hash
	fields := strings.Fields(out)
	if len(fields) < 1 || len(fields[0]) != 16 {
		t.Errorf("expected 16-char crc64 hash, got: %s", strings.TrimSpace(out))
	}
}

func TestHashFNV(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	writeTestFile(t, srcPath, "hello")

	tests := []struct {
		algo   string
		hexLen int
	}{
		{"fnv32", 8},
		{"fnv64", 16},
		{"fnv128", 32},
	}
	for _, tc := range tests {
		t.Run(tc.algo, func(t *testing.T) {
			out := captureStdout(t, func() {
				if err := cmdHash([]string{"-algo", tc.algo, srcPath}); err != nil {
					t.Fatalf("hash: %v", err)
				}
			})
			fields := strings.Fields(out)
			if len(fields) < 1 || len(fields[0]) != tc.hexLen {
				t.Errorf("expected %d-char %s hash, got: %s", tc.hexLen, tc.algo, strings.TrimSpace(out))
			}
		})
	}
}

func TestEncodeDecodeQuotedPrintable(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	// Use non-ASCII to ensure qp encoding is visible
	original := "Héllo wörld €\n"
	writeTestFile(t, srcPath, original)

	// Encode
	encoded := captureStdout(t, func() {
		if err := cmdEncode([]string{"-format", "qp", srcPath}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})

	// Should contain =XX sequences for non-ASCII bytes
	if !strings.Contains(encoded, "=C3") {
		t.Errorf("expected quoted-printable encoding with =C3 sequences, got: %s", encoded)
	}

	// Decode — write encoded output to a file and decode it
	encPath := filepath.Join(dir, "encoded.qp")
	writeTestFile(t, encPath, encoded)

	decoded := captureStdout(t, func() {
		if err := cmdDecode([]string{"-format", "qp", encPath}); err != nil {
			t.Fatalf("decode: %v", err)
		}
	})

	// cmdDecode trims whitespace from input, so trailing newline in the
	// original is lost during the round-trip through qp encoding
	if strings.TrimRight(decoded, "\n") != strings.TrimRight(original, "\n") {
		t.Errorf("round-trip failed:\n  original: %q\n  decoded:  %q", original, decoded)
	}
}

func TestEncodeDecodeUTF16(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	original := "Hello UTF-16 world!\n"
	writeTestFile(t, srcPath, original)

	// Encode to UTF-16 (binary output, so capture to file)
	utf16Path := filepath.Join(dir, "output.utf16")
	if err := cmdEncode([]string{"-format", "utf16", srcPath}); err != nil {
		// cmdEncode writes to stdout, we need to redirect — use the command directly
	}

	// Use the compress-style approach: encode to file via pipe
	// Actually, encode writes to stdout so we capture it
	var encodedBuf bytes.Buffer
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	if err := cmdEncode([]string{"-format", "utf16", srcPath}); err != nil {
		w.Close()
		os.Stdout = old
		t.Fatalf("encode: %v", err)
	}
	w.Close()
	os.Stdout = old
	io.Copy(&encodedBuf, r)

	// Write to file for decoding
	if err := os.WriteFile(utf16Path, encodedBuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	// Verify BOM is present (little-endian: FF FE)
	data := encodedBuf.Bytes()
	if len(data) < 2 || data[0] != 0xFF || data[1] != 0xFE {
		t.Error("expected UTF-16 LE BOM (FF FE)")
	}

	// Decode — utf16 format uses fmt.Println() so appends a trailing newline
	decoded := captureStdout(t, func() {
		if err := cmdDecode([]string{"-format", "utf16", utf16Path}); err != nil {
			t.Fatalf("decode: %v", err)
		}
	})

	// The original already has \n, and cmdDecode adds another \n
	expected := original + "\n"
	if decoded != expected {
		t.Errorf("round-trip failed:\n  expected: %q\n  decoded:  %q", expected, decoded)
	}
}

// ---------------------------------------------------------------------------
// encode / decode round-trips
// ---------------------------------------------------------------------------

func TestEncodeDecodeBase64(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	original := "Hello, World! 123\n"
	writeTestFile(t, srcPath, original)

	encoded := captureStdout(t, func() {
		if err := cmdEncode([]string{"-format", "base64", srcPath}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})

	encPath := filepath.Join(dir, "encoded.txt")
	writeTestFile(t, encPath, encoded)

	decoded := captureStdout(t, func() {
		if err := cmdDecode([]string{"-format", "base64", encPath}); err != nil {
			t.Fatalf("decode: %v", err)
		}
	})

	if decoded != original {
		t.Errorf("round-trip failed:\n  original: %q\n  decoded:  %q", original, decoded)
	}
}

func TestEncodeDecodeBase32(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	original := "Hello, World!"
	writeTestFile(t, srcPath, original)

	encoded := captureStdout(t, func() {
		if err := cmdEncode([]string{"-format", "base32", srcPath}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})

	encPath := filepath.Join(dir, "encoded.txt")
	writeTestFile(t, encPath, encoded)

	decoded := captureStdout(t, func() {
		if err := cmdDecode([]string{"-format", "base32", encPath}); err != nil {
			t.Fatalf("decode: %v", err)
		}
	})

	if decoded != original {
		t.Errorf("round-trip failed:\n  original: %q\n  decoded:  %q", original, decoded)
	}
}

func TestEncodeDecodeHex(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	original := "Hello"
	writeTestFile(t, srcPath, original)

	encoded := captureStdout(t, func() {
		if err := cmdEncode([]string{"-format", "hex", srcPath}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})

	if strings.TrimSpace(encoded) != "48656c6c6f" {
		t.Errorf("expected hex 48656c6c6f, got: %s", strings.TrimSpace(encoded))
	}

	encPath := filepath.Join(dir, "encoded.txt")
	writeTestFile(t, encPath, encoded)

	decoded := captureStdout(t, func() {
		if err := cmdDecode([]string{"-format", "hex", encPath}); err != nil {
			t.Fatalf("decode: %v", err)
		}
	})

	if decoded != original {
		t.Errorf("round-trip failed:\n  original: %q\n  decoded:  %q", original, decoded)
	}
}

func TestEncodeDecodeAscii85(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	original := "Hello, World!"
	writeTestFile(t, srcPath, original)

	encoded := captureStdout(t, func() {
		if err := cmdEncode([]string{"-format", "ascii85", srcPath}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})

	encPath := filepath.Join(dir, "encoded.txt")
	writeTestFile(t, encPath, encoded)

	decoded := captureStdout(t, func() {
		if err := cmdDecode([]string{"-format", "ascii85", encPath}); err != nil {
			t.Fatalf("decode: %v", err)
		}
	})

	if decoded != original {
		t.Errorf("round-trip failed:\n  original: %q\n  decoded:  %q", original, decoded)
	}
}

func TestEncodeDecodeURL(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	original := "hello world&foo=bar"
	writeTestFile(t, srcPath, original)

	encoded := captureStdout(t, func() {
		if err := cmdEncode([]string{"-format", "url", srcPath}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})

	if !strings.Contains(encoded, "%26") || !strings.Contains(encoded, "%3D") {
		t.Errorf("expected URL encoding of & and =, got: %s", strings.TrimSpace(encoded))
	}

	encPath := filepath.Join(dir, "encoded.txt")
	writeTestFile(t, encPath, encoded)

	decoded := captureStdout(t, func() {
		if err := cmdDecode([]string{"-format", "url", encPath}); err != nil {
			t.Fatalf("decode: %v", err)
		}
	})

	if decoded != original+"\n" {
		t.Errorf("round-trip failed:\n  original: %q\n  decoded:  %q", original, decoded)
	}
}

func TestEncodeDecodeHTML(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	original := `<div class="foo">bar & baz</div>`
	writeTestFile(t, srcPath, original)

	encoded := captureStdout(t, func() {
		if err := cmdEncode([]string{"-format", "html", srcPath}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})

	// Should contain HTML entities
	if !strings.Contains(encoded, "&amp;") || !strings.Contains(encoded, "&lt;") || !strings.Contains(encoded, "&gt;") {
		t.Errorf("expected HTML entities in encoded output, got: %s", strings.TrimSpace(encoded))
	}

	encPath := filepath.Join(dir, "encoded.txt")
	writeTestFile(t, encPath, encoded)

	decoded := captureStdout(t, func() {
		if err := cmdDecode([]string{"-format", "html", encPath}); err != nil {
			t.Fatalf("decode: %v", err)
		}
	})

	if decoded != original+"\n" {
		t.Errorf("round-trip failed:\n  original: %q\n  decoded:  %q", original, decoded)
	}
}

// ---------------------------------------------------------------------------
// transform modes
// ---------------------------------------------------------------------------

func TestTransformUpper(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	writeTestFile(t, srcPath, "hello world\n")

	out := captureStdout(t, func() {
		if err := cmdTransform([]string{"-mode", "upper", srcPath}); err != nil {
			t.Fatalf("transform: %v", err)
		}
	})

	if out != "HELLO WORLD\n" {
		t.Errorf("expected %q, got %q", "HELLO WORLD\n", out)
	}
}

func TestTransformLower(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	writeTestFile(t, srcPath, "HELLO WORLD\n")

	out := captureStdout(t, func() {
		if err := cmdTransform([]string{"-mode", "lower", srcPath}); err != nil {
			t.Fatalf("transform: %v", err)
		}
	})

	if out != "hello world\n" {
		t.Errorf("expected %q, got %q", "hello world\n", out)
	}
}

func TestTransformReverse(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	writeTestFile(t, srcPath, "abcdef")

	out := captureStdout(t, func() {
		if err := cmdTransform([]string{"-mode", "reverse", srcPath}); err != nil {
			t.Fatalf("transform: %v", err)
		}
	})

	if out != "fedcba" {
		t.Errorf("expected %q, got %q", "fedcba", out)
	}
}

func TestTransformGrep(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	writeTestFile(t, srcPath, "apple\nbanana\napricot\ncherry\n")

	out := captureStdout(t, func() {
		if err := cmdTransform([]string{"-mode", "grep", "-pattern", "^ap", srcPath}); err != nil {
			t.Fatalf("transform: %v", err)
		}
	})

	if out != "apple\napricot\n" {
		t.Errorf("expected %q, got %q", "apple\napricot\n", out)
	}
}

func TestTransformReplace(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	writeTestFile(t, srcPath, "foo  bar   baz")

	out := captureStdout(t, func() {
		if err := cmdTransform([]string{"-mode", "replace", "-pattern", `\s+`, "-replacement", " ", srcPath}); err != nil {
			t.Fatalf("transform: %v", err)
		}
	})

	if out != "foo bar baz" {
		t.Errorf("expected %q, got %q", "foo bar baz", out)
	}
}

func TestTransformUniq(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	writeTestFile(t, srcPath, "apple\nbanana\napple\ncherry\nbanana\n")

	out := captureStdout(t, func() {
		if err := cmdTransform([]string{"-mode", "uniq", srcPath}); err != nil {
			t.Fatalf("transform: %v", err)
		}
	})

	if out != "apple\nbanana\ncherry\n" {
		t.Errorf("expected %q, got %q", "apple\nbanana\ncherry\n", out)
	}
}

// ---------------------------------------------------------------------------
// hash: multi-algorithm output length
// ---------------------------------------------------------------------------

func TestHashAlgorithms(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	writeTestFile(t, srcPath, "test data for hashing")

	tests := []struct {
		algo   string
		hexLen int
	}{
		{"md5", 32},
		{"sha1", 40},
		{"sha256", 64},
		{"sha512", 128},
		{"sha3-256", 64},
		{"sha3-512", 128},
		{"crc32", 8},
	}
	for _, tc := range tests {
		t.Run(tc.algo, func(t *testing.T) {
			out := captureStdout(t, func() {
				if err := cmdHash([]string{"-algo", tc.algo, srcPath}); err != nil {
					t.Fatalf("hash: %v", err)
				}
			})
			fields := strings.Fields(out)
			if len(fields) < 1 {
				t.Fatal("no output")
			}
			if len(fields[0]) != tc.hexLen {
				t.Errorf("%s: expected %d hex chars, got %d (%s)", tc.algo, tc.hexLen, len(fields[0]), fields[0])
			}
		})
	}
}

// ---------------------------------------------------------------------------
// hash: HMAC mode
// ---------------------------------------------------------------------------

func TestHashHMAC(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	writeTestFile(t, srcPath, "hmac test data")

	// Plain hash without HMAC
	plain := captureStdout(t, func() {
		if err := cmdHash([]string{"-algo", "sha256", srcPath}); err != nil {
			t.Fatalf("hash: %v", err)
		}
	})

	// Hash with HMAC key
	hmacOut := captureStdout(t, func() {
		if err := cmdHash([]string{"-algo", "sha256", "-hmac", "secret-key", srcPath}); err != nil {
			t.Fatalf("hash: %v", err)
		}
	})

	plainHash := strings.Fields(plain)[0]
	hmacHash := strings.Fields(hmacOut)[0]

	// HMAC output should differ from plain hash
	if plainHash == hmacHash {
		t.Error("HMAC hash should differ from plain hash")
	}

	// HMAC should be deterministic
	hmacOut2 := captureStdout(t, func() {
		if err := cmdHash([]string{"-algo", "sha256", "-hmac", "secret-key", srcPath}); err != nil {
			t.Fatalf("hash: %v", err)
		}
	})
	if strings.Fields(hmacOut2)[0] != hmacHash {
		t.Error("HMAC output is not deterministic")
	}

	// Different key should produce different HMAC
	hmacOut3 := captureStdout(t, func() {
		if err := cmdHash([]string{"-algo", "sha256", "-hmac", "different-key", srcPath}); err != nil {
			t.Fatalf("hash: %v", err)
		}
	})
	if strings.Fields(hmacOut3)[0] == hmacHash {
		t.Error("different HMAC keys produced identical output")
	}
}

// ---------------------------------------------------------------------------
// archive: extract round-trips
// ---------------------------------------------------------------------------

func TestArchiveExtractTarGz(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	os.MkdirAll(srcDir, 0o755)
	writeTestFile(t, filepath.Join(srcDir, "a.txt"), "alpha content")
	writeTestFile(t, filepath.Join(srcDir, "b.txt"), "bravo content")

	archivePath := filepath.Join(dir, "test.tar.gz")
	if err := createTarGz(archivePath, []string{
		filepath.Join(srcDir, "a.txt"),
		filepath.Join(srcDir, "b.txt"),
	}); err != nil {
		t.Fatalf("createTarGz: %v", err)
	}

	destDir := filepath.Join(dir, "dest")
	os.MkdirAll(destDir, 0o755)

	if err := extractArchive(archivePath, destDir); err != nil {
		t.Fatalf("extractArchive: %v", err)
	}

	// The extracted paths include the full original paths
	for _, name := range []string{"a.txt", "b.txt"} {
		extractedPath := filepath.Join(destDir, srcDir, name)
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
	if err := createZip(archivePath, []string{
		filepath.Join(srcDir, "x.txt"),
		filepath.Join(srcDir, "y.txt"),
	}); err != nil {
		t.Fatalf("createZip: %v", err)
	}

	destDir := filepath.Join(dir, "dest")
	os.MkdirAll(destDir, 0o755)

	if err := extractArchive(archivePath, destDir); err != nil {
		t.Fatalf("extractArchive: %v", err)
	}

	for _, name := range []string{"x.txt", "y.txt"} {
		extractedPath := filepath.Join(destDir, srcDir, name)
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

// ---------------------------------------------------------------------------
// archive: createTarZlib round-trip
// ---------------------------------------------------------------------------

func TestCreateTarZlib(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "a.txt"), "alpha")
	writeTestFile(t, filepath.Join(dir, "b.txt"), "bravo")

	archivePath := filepath.Join(dir, "out.tar.zlib")
	if err := createTarZlib(archivePath, []string{
		filepath.Join(dir, "a.txt"),
		filepath.Join(dir, "b.txt"),
	}); err != nil {
		t.Fatalf("createTarZlib: %v", err)
	}

	// Extract and verify
	destDir := filepath.Join(dir, "dest")
	os.MkdirAll(destDir, 0o755)

	if err := extractArchive(archivePath, destDir); err != nil {
		t.Fatalf("extractArchive tar.zlib: %v", err)
	}

	for _, tc := range []struct{ name, want string }{
		{"a.txt", "alpha"},
		{"b.txt", "bravo"},
	} {
		// Find the extracted file (path includes original dir structure)
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

// ---------------------------------------------------------------------------
// compress: level affects output size
// ---------------------------------------------------------------------------

func TestCompressGzipLevels(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	original := strings.Repeat("compress level test data with some repetition\n", 200)
	writeTestFile(t, srcPath, original)

	fast := filepath.Join(dir, "fast.gz")
	best := filepath.Join(dir, "best.gz")

	if err := cmdCompress([]string{"-format", "gzip", "-level", "1", srcPath, fast}); err != nil {
		t.Fatalf("compress level 1: %v", err)
	}
	if err := cmdCompress([]string{"-format", "gzip", "-level", "9", srcPath, best}); err != nil {
		t.Fatalf("compress level 9: %v", err)
	}

	fastStat, _ := os.Stat(fast)
	bestStat, _ := os.Stat(best)

	if bestStat.Size() >= fastStat.Size() {
		t.Errorf("level 9 (%d bytes) should be smaller than level 1 (%d bytes)", bestStat.Size(), fastStat.Size())
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// assertContains checks that output contains a line with both label and value.
func assertContains(t *testing.T, output, label, value string) {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, label) && strings.Contains(line, value) {
			return
		}
	}
	t.Errorf("output missing %s %s\n--- output ---\n%s", label, value, output)
}
