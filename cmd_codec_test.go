package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncodeDecodeQuotedPrintable(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	original := "Héllo wörld €\n"
	writeTestFile(t, srcPath, original)

	encoded := captureStdout(t, func() {
		if err := cmdEncode([]string{"-format", "qp", srcPath}); err != nil {
			t.Fatalf("encode: %v", err)
		}
	})

	if !strings.Contains(encoded, "=C3") {
		t.Errorf("expected quoted-printable encoding with =C3 sequences, got: %s", encoded)
	}

	encPath := filepath.Join(dir, "encoded.qp")
	writeTestFile(t, encPath, encoded)

	decoded := captureStdout(t, func() {
		if err := cmdDecode([]string{"-format", "qp", encPath}); err != nil {
			t.Fatalf("decode: %v", err)
		}
	})

	if strings.TrimRight(decoded, "\n") != strings.TrimRight(original, "\n") {
		t.Errorf("round-trip failed:\n  original: %q\n  decoded:  %q", original, decoded)
	}
}

func TestEncodeDecodeUTF16(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	original := "Hello UTF-16 world!\n"
	writeTestFile(t, srcPath, original)

	utf16Path := filepath.Join(dir, "output.utf16")

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

	if err := os.WriteFile(utf16Path, encodedBuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	data := encodedBuf.Bytes()
	if len(data) < 2 || data[0] != 0xFF || data[1] != 0xFE {
		t.Error("expected UTF-16 LE BOM (FF FE)")
	}

	decoded := captureStdout(t, func() {
		if err := cmdDecode([]string{"-format", "utf16", utf16Path}); err != nil {
			t.Fatalf("decode: %v", err)
		}
	})

	expected := original + "\n"
	if decoded != expected {
		t.Errorf("round-trip failed:\n  expected: %q\n  decoded:  %q", expected, decoded)
	}
}

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
