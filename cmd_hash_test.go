package main

import (
	"path/filepath"
	"strings"
	"testing"
)

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

func TestHashHMAC(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	writeTestFile(t, srcPath, "hmac test data")

	plain := captureStdout(t, func() {
		if err := cmdHash([]string{"-algo", "sha256", srcPath}); err != nil {
			t.Fatalf("hash: %v", err)
		}
	})

	hmacOut := captureStdout(t, func() {
		if err := cmdHash([]string{"-algo", "sha256", "-hmac", "secret-key", srcPath}); err != nil {
			t.Fatalf("hash: %v", err)
		}
	})

	plainHash := strings.Fields(plain)[0]
	hmacHash := strings.Fields(hmacOut)[0]

	if plainHash == hmacHash {
		t.Error("HMAC hash should differ from plain hash")
	}

	hmacOut2 := captureStdout(t, func() {
		if err := cmdHash([]string{"-algo", "sha256", "-hmac", "secret-key", srcPath}); err != nil {
			t.Fatalf("hash: %v", err)
		}
	})
	if strings.Fields(hmacOut2)[0] != hmacHash {
		t.Error("HMAC output is not deterministic")
	}

	hmacOut3 := captureStdout(t, func() {
		if err := cmdHash([]string{"-algo", "sha256", "-hmac", "different-key", srcPath}); err != nil {
			t.Fatalf("hash: %v", err)
		}
	})
	if strings.Fields(hmacOut3)[0] == hmacHash {
		t.Error("different HMAC keys produced identical output")
	}
}
