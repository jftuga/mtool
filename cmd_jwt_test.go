package main

import (
	"encoding/base64"
	"github.com/jftuga/mtool/internal/jwt"
	"strings"
	"testing"
)

func TestDecodeJWT(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1234567890","name":"John Doe","iat":1516239022}`))
	token := header + "." + payload + ".fakesignature"

	hdr, pl, err := jwt.DecodeJWT(token)
	if err != nil {
		t.Fatalf("DecodeJWT: %v", err)
	}

	if hdr["alg"] != "HS256" {
		t.Errorf("header alg = %v, want HS256", hdr["alg"])
	}
	if hdr["typ"] != "JWT" {
		t.Errorf("header typ = %v, want JWT", hdr["typ"])
	}
	if pl["sub"] != "1234567890" {
		t.Errorf("payload sub = %v, want 1234567890", pl["sub"])
	}
	if pl["name"] != "John Doe" {
		t.Errorf("payload name = %v, want John Doe", pl["name"])
	}
}

func TestDecodeJWTInvalid(t *testing.T) {
	tests := []string{
		"notajwt",
		"two.parts",
		"four.parts.here.extra",
		"",
	}
	for _, token := range tests {
		t.Run(token, func(t *testing.T) {
			_, _, err := jwt.DecodeJWT(token)
			if err == nil {
				t.Error("expected error for invalid JWT")
			}
		})
	}
}

func TestFormatJWTExpiry(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		payload := map[string]interface{}{
			"exp": float64(1000000000),
		}
		result := jwt.FormatJWTExpiry(payload)
		if !strings.Contains(result, "EXPIRED") {
			t.Errorf("expected EXPIRED in output, got: %s", result)
		}
	})

	t.Run("future", func(t *testing.T) {
		payload := map[string]interface{}{
			"exp": float64(9999999999),
		}
		result := jwt.FormatJWTExpiry(payload)
		if !strings.Contains(result, "valid for") {
			t.Errorf("expected 'valid for' in output, got: %s", result)
		}
	})

	t.Run("no exp", func(t *testing.T) {
		payload := map[string]interface{}{
			"sub": "user",
		}
		result := jwt.FormatJWTExpiry(payload)
		if result != "" {
			t.Errorf("expected empty string for no exp, got: %s", result)
		}
	})

	t.Run("iat and nbf", func(t *testing.T) {
		payload := map[string]interface{}{
			"iat": float64(1516239022),
			"nbf": float64(1516239022),
		}
		result := jwt.FormatJWTExpiry(payload)
		if !strings.Contains(result, "Issued At:") {
			t.Errorf("expected 'Issued At:' in output, got: %s", result)
		}
		if !strings.Contains(result, "Not Before:") {
			t.Errorf("expected 'Not Before:' in output, got: %s", result)
		}
	})
}

func TestJWTFromArg(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test","exp":9999999999}`))
	token := header + "." + payload + ".sig"

	out := captureStdout(t, func() {
		if err := cmdJWT([]string{token}); err != nil {
			t.Fatalf("cmdJWT: %v", err)
		}
	})

	if !strings.Contains(out, "Header:") {
		t.Error("output missing Header: label")
	}
	if !strings.Contains(out, "Payload:") {
		t.Error("output missing Payload: label")
	}
	if !strings.Contains(out, "HS256") {
		t.Error("output missing algorithm")
	}
}
