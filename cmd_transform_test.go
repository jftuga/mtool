package main

import (
	"mtool/internal/transform"
	"os"
	"strings"
	"testing"
)

func TestSortLines(t *testing.T) {
	t.Run("alphabetical", func(t *testing.T) {
		input := "cherry\napple\nbanana\n"
		got := captureStdout(t, func() { transform.SortLines(input, false, false, false, 0, os.Stdout) })
		want := "apple\nbanana\ncherry\n"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("reverse alphabetical", func(t *testing.T) {
		input := "cherry\napple\nbanana\n"
		got := captureStdout(t, func() { transform.SortLines(input, false, true, false, 0, os.Stdout) })
		want := "cherry\nbanana\napple\n"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("numeric", func(t *testing.T) {
		input := "10\n2\n1\n20\n3\n"
		got := captureStdout(t, func() { transform.SortLines(input, true, false, false, 0, os.Stdout) })
		want := "1\n2\n3\n10\n20\n"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("numeric descending", func(t *testing.T) {
		input := "10\n2\n1\n20\n3\n"
		got := captureStdout(t, func() { transform.SortLines(input, true, true, false, 0, os.Stdout) })
		want := "20\n10\n3\n2\n1\n"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("case insensitive", func(t *testing.T) {
		input := "Banana\napple\nCherry\n"
		got := captureStdout(t, func() { transform.SortLines(input, false, false, true, 0, os.Stdout) })
		want := "apple\nBanana\nCherry\n"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("by field", func(t *testing.T) {
		input := "alice 30\nbob 20\ncharlie 25\n"
		got := captureStdout(t, func() { transform.SortLines(input, true, false, false, 2, os.Stdout) })
		want := "bob 20\ncharlie 25\nalice 30\n"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("field out of range sorts as empty", func(t *testing.T) {
		input := "one\ntwo\nthree\n"
		got := captureStdout(t, func() { transform.SortLines(input, false, false, false, 5, os.Stdout) })
		want := "one\ntwo\nthree\n"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("numeric with non-numeric lines", func(t *testing.T) {
		input := "5\nfoo\n1\nbar\n10\n"
		got := captureStdout(t, func() { transform.SortLines(input, true, false, false, 0, os.Stdout) })
		lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
		if lines[0] != "1" || lines[1] != "5" || lines[2] != "10" {
			t.Errorf("numeric lines not sorted first: %v", lines)
		}
	})
}

func TestPrintTextStats(t *testing.T) {
	t.Run("basic counts", func(t *testing.T) {
		input := "Hello World 123\nFoo\n"
		got := captureStdout(t, func() { transform.PrintTextStats(input, os.Stdout) })
		assertContains(t, got, "Lines:", "2")
		assertContains(t, got, "Words:", "4")
		assertContains(t, got, "Letters:", "13")
		assertContains(t, got, "Digits:", "3")
	})

	t.Run("empty string", func(t *testing.T) {
		got := captureStdout(t, func() { transform.PrintTextStats("", os.Stdout) })
		assertContains(t, got, "Words:", "0")
		assertContains(t, got, "Bytes:", "0")
	})

	t.Run("no trailing newline still counts as a line", func(t *testing.T) {
		got := captureStdout(t, func() { transform.PrintTextStats("hello", os.Stdout) })
		assertContains(t, got, "Lines:", "1")
	})

	t.Run("unicode characters", func(t *testing.T) {
		input := "Hej!"
		got := captureStdout(t, func() { transform.PrintTextStats(input, os.Stdout) })
		assertContains(t, got, "Characters:", "4")
		assertContains(t, got, "Letters:", "3")
	})
}

func TestPrintWordFrequency(t *testing.T) {
	t.Run("frequency ordering", func(t *testing.T) {
		input := "the cat sat on the mat the cat"
		got := captureStdout(t, func() { transform.PrintWordFrequency(input, os.Stdout) })
		lines := strings.Split(strings.TrimSpace(got), "\n")
		if len(lines) < 2 {
			t.Fatalf("expected at least a header + 1 data line, got %d lines", len(lines))
		}
		if !strings.Contains(lines[0], "WORD") {
			t.Errorf("missing header, got: %q", lines[0])
		}
		if !strings.Contains(lines[1], "the") || !strings.Contains(lines[1], "3") {
			t.Errorf("expected 'the 3' first, got: %q", lines[1])
		}
	})

	t.Run("case insensitive", func(t *testing.T) {
		input := "Go go GO"
		got := captureStdout(t, func() { transform.PrintWordFrequency(input, os.Stdout) })
		if !strings.Contains(got, "3") {
			t.Errorf("expected 'go' counted 3 times, got: %s", got)
		}
	})
}

func TestTransformUpper(t *testing.T) {
	dir := t.TempDir()
	srcPath := dir + "/input.txt"
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
	srcPath := dir + "/input.txt"
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

func TestTransformTitle(t *testing.T) {
	dir := t.TempDir()
	srcPath := dir + "/input.txt"
	writeTestFile(t, srcPath, "hello world\n")
	out := captureStdout(t, func() {
		if err := cmdTransform([]string{"-mode", "title", srcPath}); err != nil {
			t.Fatalf("transform: %v", err)
		}
	})
	if out != "Hello World\n" {
		t.Errorf("expected %q, got %q", "Hello World\n", out)
	}
}

func TestTransformTitleMixedCase(t *testing.T) {
	dir := t.TempDir()
	srcPath := dir + "/input.txt"
	writeTestFile(t, srcPath, "hELLO wORLD")
	out := captureStdout(t, func() {
		if err := cmdTransform([]string{"-mode", "title", srcPath}); err != nil {
			t.Fatalf("transform: %v", err)
		}
	})
	if out != "Hello World" {
		t.Errorf("expected %q, got %q", "Hello World", out)
	}
}

func TestTransformReverse(t *testing.T) {
	dir := t.TempDir()
	srcPath := dir + "/input.txt"
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
	srcPath := dir + "/input.txt"
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
	srcPath := dir + "/input.txt"
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
	srcPath := dir + "/input.txt"
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
