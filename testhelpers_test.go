package main

import (
	"io"
	"os"
	"strings"
	"testing"
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

// writeTestFile writes test data to a file.
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
