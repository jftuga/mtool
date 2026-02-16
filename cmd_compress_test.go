package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompressDecompressGzip(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "input.txt")
	compPath := filepath.Join(dir, "input.txt.gz")
	decPath := filepath.Join(dir, "output.txt")

	original := strings.Repeat("the quick brown fox jumps over the lazy dog\n", 100)
	writeTestFile(t, srcPath, original)

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
	tests := []struct {
		litwidth string
		data     string
	}{
		{"6", strings.Repeat("\x01\x02\x03\x10\x20\x3F", 100)},
		{"7", strings.Repeat("LZW test 01234\n", 100)},
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

			if err := cmdCompress([]string{"-format", "lzw", "-litwidth", tc.litwidth, srcPath, compPath}); err != nil {
				t.Fatalf("compress: %v", err)
			}

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

			if err := cmdCompress([]string{"-d", "-format", "lzw", compPath, decPath}); err != nil {
				t.Fatalf("decompress: %v", err)
			}

			decData, err := os.ReadFile(decPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decData, []byte(tc.data)) {
				t.Error("decompressed data does not match original")
			}
		})
	}
}

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
