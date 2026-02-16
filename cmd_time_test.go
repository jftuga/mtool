package main

import (
	"mtool/internal/timecmd"
	"strings"
	"testing"
)

func TestParseFlexibleTime(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"2024-01-15T10:30:00Z", false},
		{"2024-01-15T10:30:00+05:00", false},
		{"2024-01-15", false},
		{"01/15/2024", false},
		{"Jan 15, 2024", false},
		{"January 15, 2024", false},
		{"15 Jan 2024", false},
		{"2024-01-15 10:30:00", false},
		{"01/15/2024 10:30:00", false},
		{"Jan 15, 2024 10:30:00", false},
		{"1700000000", false},
		{"not-a-date", true},
		{"", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := timecmd.ParseFlexibleTime(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseFlexibleTime(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestTimeNow(t *testing.T) {
	out := captureStdout(t, func() {
		if err := cmdTime([]string{"-mode", "now"}); err != nil {
			t.Fatalf("cmdTime now: %v", err)
		}
	})
	for _, label := range []string{"Local:", "UTC:", "RFC3339:", "Epoch:"} {
		if !strings.Contains(out, label) {
			t.Errorf("output missing %q label", label)
		}
	}
}

func TestTimeFromEpoch(t *testing.T) {
	t.Run("epoch zero", func(t *testing.T) {
		out := captureStdout(t, func() {
			if err := cmdTime([]string{"-mode", "fromepoch", "0"}); err != nil {
				t.Fatalf("cmdTime fromepoch: %v", err)
			}
		})
		if !strings.Contains(out, "1970-01-01") {
			t.Errorf("expected 1970-01-01 in output, got: %s", out)
		}
	})

	t.Run("known epoch", func(t *testing.T) {
		out := captureStdout(t, func() {
			if err := cmdTime([]string{"-mode", "fromepoch", "1700000000"}); err != nil {
				t.Fatalf("cmdTime fromepoch: %v", err)
			}
		})
		if !strings.Contains(out, "2023-11-14") {
			t.Errorf("expected 2023-11-14 in output, got: %s", out)
		}
	})
}

func TestTimeToEpoch(t *testing.T) {
	out := captureStdout(t, func() {
		if err := cmdTime([]string{"-mode", "toepoch", "2024-01-01T00:00:00Z"}); err != nil {
			t.Fatalf("cmdTime toepoch: %v", err)
		}
	})
	if strings.TrimSpace(out) != "1704067200" {
		t.Errorf("expected epoch 1704067200, got: %s", strings.TrimSpace(out))
	}
}

func TestTimeConvert(t *testing.T) {
	out := captureStdout(t, func() {
		if err := cmdTime([]string{"-mode", "convert", "-zone", "UTC", "2024-01-01T00:00:00Z"}); err != nil {
			t.Fatalf("cmdTime convert: %v", err)
		}
	})
	if !strings.Contains(out, "2024-01-01") && !strings.Contains(out, "UTC") {
		t.Errorf("expected UTC converted time, got: %s", out)
	}
}
