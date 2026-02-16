package main

import (
	"mtool/internal/inspect"
	"testing"
)

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
		got := inspect.TLSVersionString(tt.input)
		if got != tt.want {
			t.Errorf("TLSVersionString(0x%04x) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
