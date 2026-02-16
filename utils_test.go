package main

import (
	"fmt"
	"mtool/internal/shared"
	"path/filepath"
	"testing"
)

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
			got := shared.FormatSize(tt.input)
			if got != tt.want {
				t.Errorf("FormatSize(%d) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestReadInput(t *testing.T) {
	t.Run("reads from file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "input.txt")
		writeTestFile(t, path, "hello from file")
		data, err := shared.ReadInput([]string{path})
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "hello from file" {
			t.Errorf("got %q, want %q", string(data), "hello from file")
		}
	})

	t.Run("returns error for missing file", func(t *testing.T) {
		_, err := shared.ReadInput([]string{"/nonexistent/path/file.txt"})
		if err == nil {
			t.Error("expected error for missing file, got nil")
		}
	})
}

func TestCryptoRandIntn(t *testing.T) {
	for _, n := range []int{1, 10, 100, 1000} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			for range 50 {
				val, err := shared.CryptoRandIntn(n)
				if err != nil {
					t.Fatal(err)
				}
				if val < 0 || val >= n {
					t.Errorf("CryptoRandIntn(%d) = %d, out of range [0, %d)", n, val, n)
				}
			}
		})
	}
}
