package main

import (
	"mtool/internal/jsoncmd"
	"path/filepath"
	"strings"
	"testing"
)

func TestJSONPretty(t *testing.T) {
	input := []byte(`{"name":"alice","age":30}`)
	result, err := jsoncmd.JSONPretty(input, "  ")
	if err != nil {
		t.Fatalf("JSONPretty: %v", err)
	}
	if !strings.Contains(result, "\n") {
		t.Error("pretty output should contain newlines")
	}
	if !strings.Contains(result, "  ") {
		t.Error("pretty output should contain indentation")
	}
	if !strings.Contains(result, `"name"`) {
		t.Error("pretty output should contain original keys")
	}
}

func TestJSONCompact(t *testing.T) {
	input := []byte("{\n  \"name\": \"alice\",\n  \"age\": 30\n}")
	result, err := jsoncmd.JSONCompact(input)
	if err != nil {
		t.Fatalf("JSONCompact: %v", err)
	}
	if strings.Contains(result, "\n") {
		t.Error("compact output should not contain newlines")
	}
	if result != `{"name":"alice","age":30}` {
		t.Errorf("unexpected compact output: %s", result)
	}
}

func TestJSONValidate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		dir := t.TempDir()
		srcPath := filepath.Join(dir, "valid.json")
		writeTestFile(t, srcPath, `{"key":"value"}`)
		out := captureStdout(t, func() {
			err := cmdJSON([]string{"-mode", "validate", srcPath})
			if err != nil {
				t.Errorf("expected nil error for valid JSON, got: %v", err)
			}
		})
		if !strings.Contains(out, "valid") {
			t.Errorf("expected 'valid' in output, got: %s", out)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		dir := t.TempDir()
		srcPath := filepath.Join(dir, "invalid.json")
		writeTestFile(t, srcPath, `{not json}`)
		captureStdout(t, func() {
			err := cmdJSON([]string{"-mode", "validate", srcPath})
			if err == nil {
				t.Error("expected error for invalid JSON, got nil")
			}
		})
	})
}

func TestJSONQuery(t *testing.T) {
	data := []byte(`{"user":{"name":"alice","scores":[10,20,30]},"items":[{"id":1},{"id":2}]}`)

	t.Run("nested key", func(t *testing.T) {
		result, err := jsoncmd.JSONQuery(data, ".user.name")
		if err != nil {
			t.Fatalf("JSONQuery: %v", err)
		}
		if result != "alice" {
			t.Errorf("expected alice, got: %v", result)
		}
	})

	t.Run("array index", func(t *testing.T) {
		result, err := jsoncmd.JSONQuery(data, ".user.scores[1]")
		if err != nil {
			t.Fatalf("JSONQuery: %v", err)
		}
		if result != float64(20) {
			t.Errorf("expected 20, got: %v", result)
		}
	})

	t.Run("nested array object", func(t *testing.T) {
		result, err := jsoncmd.JSONQuery(data, ".items[0].id")
		if err != nil {
			t.Fatalf("JSONQuery: %v", err)
		}
		if result != float64(1) {
			t.Errorf("expected 1, got: %v", result)
		}
	})

	t.Run("missing key", func(t *testing.T) {
		_, err := jsoncmd.JSONQuery(data, ".user.missing")
		if err == nil {
			t.Error("expected error for missing key")
		}
	})

	t.Run("out of range index", func(t *testing.T) {
		_, err := jsoncmd.JSONQuery(data, ".user.scores[99]")
		if err == nil {
			t.Error("expected error for out of range index")
		}
	})
}
