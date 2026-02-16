package main

import (
	"fmt"
	"mtool/internal/generate"
	"regexp"
	"testing"
	"unicode"
)

func TestGeneratePassword(t *testing.T) {
	t.Run("alpha only", func(t *testing.T) {
		pw, err := generate.GeneratePassword(30, "alpha")
		if err != nil {
			t.Fatal(err)
		}
		if len(pw) != 30 {
			t.Errorf("length = %d, want 30", len(pw))
		}
		for _, r := range pw {
			if !unicode.IsLetter(r) {
				t.Errorf("non-letter rune %q in alpha password", r)
			}
		}
	})

	t.Run("alnum only", func(t *testing.T) {
		pw, err := generate.GeneratePassword(30, "alnum")
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range pw {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
				t.Errorf("unexpected rune %q in alnum password", r)
			}
		}
	})

	t.Run("full charset has mixed categories", func(t *testing.T) {
		for range 10 {
			pw, err := generate.GeneratePassword(20, "full")
			if err != nil {
				t.Fatal(err)
			}
			if len(pw) != 20 {
				t.Errorf("length = %d, want 20", len(pw))
			}
			hasLower, hasUpper, hasDigit, hasSpecial := false, false, false, false
			for _, r := range pw {
				switch {
				case unicode.IsLower(r):
					hasLower = true
				case unicode.IsUpper(r):
					hasUpper = true
				case unicode.IsDigit(r):
					hasDigit = true
				default:
					hasSpecial = true
				}
			}
			if hasLower && hasUpper && hasDigit && hasSpecial {
				return
			}
		}
		t.Error("full charset password never contained all four categories in 10 attempts")
	})

	t.Run("respects length", func(t *testing.T) {
		for _, length := range []int{1, 4, 8, 50, 128} {
			pw, err := generate.GeneratePassword(length, "alnum")
			if err != nil {
				t.Fatal(err)
			}
			if len(pw) != length {
				t.Errorf("GeneratePassword(%d, alnum): length = %d", length, len(pw))
			}
		}
	})
}

func TestGenerateToken(t *testing.T) {
	hexRe := regexp.MustCompile(`^[0-9a-f]+$`)

	for _, length := range []int{8, 16, 32, 64} {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			tok, err := generate.GenerateToken(length)
			if err != nil {
				t.Fatal(err)
			}
			if len(tok) != length {
				t.Errorf("token length = %d, want %d", len(tok), length)
			}
			if !hexRe.MatchString(tok) {
				t.Errorf("token %q contains non-hex characters", tok)
			}
		})
	}

	t.Run("uniqueness", func(t *testing.T) {
		a, _ := generate.GenerateToken(32)
		b, _ := generate.GenerateToken(32)
		if a == b {
			t.Error("two generated tokens are identical")
		}
	})
}

func TestGenerateUUID(t *testing.T) {
	uuidRe := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

	for range 20 {
		uuid, err := generate.GenerateUUID()
		if err != nil {
			t.Fatal(err)
		}
		if !uuidRe.MatchString(uuid) {
			t.Errorf("UUID %q does not match v4 format", uuid)
		}
	}

	t.Run("uniqueness", func(t *testing.T) {
		a, _ := generate.GenerateUUID()
		b, _ := generate.GenerateUUID()
		if a == b {
			t.Error("two generated UUIDs are identical")
		}
	})
}

func TestGenerateBigInt(t *testing.T) {
	for _, bits := range []int{8, 64, 128, 256} {
		t.Run(fmt.Sprintf("%d_bits", bits), func(t *testing.T) {
			s, err := generate.GenerateBigInt(bits)
			if err != nil {
				t.Fatal(err)
			}
			if s == "" {
				t.Error("empty string returned")
			}
			for _, r := range s {
				if !unicode.IsDigit(r) {
					t.Errorf("non-digit rune %q in bigint output %q", r, s)
				}
			}
		})
	}
}
