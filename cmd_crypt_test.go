package main

import (
	"bytes"
	"mtool/internal/crypt"
	"os"
	"path/filepath"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	mustDeriveKey := func(t *testing.T, password, salt []byte) []byte {
		t.Helper()
		key, err := crypt.DeriveKey(password, salt)
		if err != nil {
			t.Fatalf("DeriveKey: %v", err)
		}
		return key
	}

	t.Run("deterministic", func(t *testing.T) {
		salt := []byte("fixed-salt-value")
		key1 := mustDeriveKey(t, []byte("password"), salt)
		key2 := mustDeriveKey(t, []byte("password"), salt)
		if !bytes.Equal(key1, key2) {
			t.Error("same password+salt produced different keys")
		}
	})

	t.Run("correct length", func(t *testing.T) {
		key := mustDeriveKey(t, []byte("password"), []byte("salt"))
		if len(key) != 32 {
			t.Errorf("key length = %d, want 32", len(key))
		}
	})

	t.Run("different passwords differ", func(t *testing.T) {
		salt := []byte("same-salt")
		k1 := mustDeriveKey(t, []byte("password1"), salt)
		k2 := mustDeriveKey(t, []byte("password2"), salt)
		if bytes.Equal(k1, k2) {
			t.Error("different passwords produced identical keys")
		}
	})

	t.Run("different salts differ", func(t *testing.T) {
		k1 := mustDeriveKey(t, []byte("password"), []byte("salt-a"))
		k2 := mustDeriveKey(t, []byte("password"), []byte("salt-b"))
		if bytes.Equal(k1, k2) {
			t.Error("different salts produced identical keys")
		}
	})
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "secret.txt")
	encPath := filepath.Join(dir, "secret.enc")
	decPath := filepath.Join(dir, "secret.dec")
	password := "correct-horse-battery-staple"

	original := "This is sensitive data that must survive encryption.\n"
	writeTestFile(t, plainPath, original)

	if err := cmdEncrypt([]string{"-password", password, plainPath, encPath}); err != nil {
		t.Fatalf("cmdEncrypt: %v", err)
	}

	encData, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(encData) == original {
		t.Error("encrypted data is identical to plaintext")
	}
	if len(encData) <= len(original) {
		t.Errorf("encrypted size (%d) should exceed plaintext size (%d)", len(encData), len(original))
	}

	if err := cmdDecrypt([]string{"-password", password, encPath, decPath}); err != nil {
		t.Fatalf("cmdDecrypt: %v", err)
	}

	decData, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(decData) != original {
		t.Errorf("decrypted = %q, want %q", string(decData), original)
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "data.txt")
	encPath := filepath.Join(dir, "data.enc")
	decPath := filepath.Join(dir, "data.dec")

	writeTestFile(t, plainPath, "secret stuff")

	if err := cmdEncrypt([]string{"-password", "right", plainPath, encPath}); err != nil {
		t.Fatal(err)
	}

	err := cmdDecrypt([]string{"-password", "wrong", encPath, decPath})
	if err == nil {
		t.Error("expected error decrypting with wrong password, got nil")
	}
}

func TestEncryptProducesUniqueOutput(t *testing.T) {
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "data.txt")
	enc1 := filepath.Join(dir, "out1.enc")
	enc2 := filepath.Join(dir, "out2.enc")

	writeTestFile(t, plainPath, "same input twice")

	if err := cmdEncrypt([]string{"-password", "pass", plainPath, enc1}); err != nil {
		t.Fatal(err)
	}
	if err := cmdEncrypt([]string{"-password", "pass", plainPath, enc2}); err != nil {
		t.Fatal(err)
	}

	d1, _ := os.ReadFile(enc1)
	d2, _ := os.ReadFile(enc2)
	if bytes.Equal(d1, d2) {
		t.Error("two encryptions of the same file produced identical output (salt/nonce should differ)")
	}
}
