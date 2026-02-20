package main

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/jftuga/mtool/internal/serve"
	"net"
	"strings"
	"testing"
	"time"
)

func TestLoadDirectoryTemplate(t *testing.T) {
	tmpl, err := serve.LoadDirectoryTemplate()
	if err != nil {
		t.Fatalf("LoadDirectoryTemplate: %v", err)
	}

	data := struct {
		Path    string
		Entries []serve.DirEntry
	}{
		Path: "/test",
		Entries: []serve.DirEntry{
			{Name: "file.txt", Link: "file.txt", Size: "1.0 KB", ModTime: "2025-01-01 00:00:00", IsDir: false},
			{Name: "subdir", Link: "subdir", Size: "-", ModTime: "2025-01-01 00:00:00", IsDir: true},
		},
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("template execute: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "/test") {
		t.Error("rendered HTML missing path")
	}
	if !strings.Contains(html, "file.txt") {
		t.Error("rendered HTML missing file entry")
	}
	if !strings.Contains(html, "subdir") {
		t.Error("rendered HTML missing directory entry")
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	tlsCert, err := serve.GenerateSelfSignedCert()
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}

	if len(tlsCert.Certificate) == 0 {
		t.Fatal("no certificate data in TLS certificate")
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing leaf certificate: %v", err)
	}

	t.Run("subject", func(t *testing.T) {
		if leaf.Subject.CommonName != "localhost" {
			t.Errorf("CommonName = %q, want %q", leaf.Subject.CommonName, "localhost")
		}
	})

	t.Run("self-signed", func(t *testing.T) {
		if leaf.Issuer.CommonName != leaf.Subject.CommonName {
			t.Errorf("Issuer CN = %q, Subject CN = %q — expected self-signed", leaf.Issuer.CommonName, leaf.Subject.CommonName)
		}
	})

	t.Run("validity window", func(t *testing.T) {
		now := time.Now()
		if now.Before(leaf.NotBefore) {
			t.Errorf("certificate not yet valid (NotBefore: %s)", leaf.NotBefore)
		}
		if now.After(leaf.NotAfter) {
			t.Errorf("certificate already expired (NotAfter: %s)", leaf.NotAfter)
		}
		remaining := time.Until(leaf.NotAfter)
		if remaining < 23*time.Hour || remaining > 25*time.Hour {
			t.Errorf("expected ~24h validity, got %s", remaining)
		}
	})

	t.Run("DNS names", func(t *testing.T) {
		found := false
		for _, name := range leaf.DNSNames {
			if name == "localhost" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DNS names %v missing 'localhost'", leaf.DNSNames)
		}
	})

	t.Run("IP addresses", func(t *testing.T) {
		hasLoopback := false
		for _, ip := range leaf.IPAddresses {
			if ip.Equal(net.IPv4(127, 0, 0, 1)) || ip.Equal(net.IPv6loopback) {
				hasLoopback = true
				break
			}
		}
		if !hasLoopback {
			t.Errorf("IP addresses %v missing loopback", leaf.IPAddresses)
		}
	})

	t.Run("usable by tls.Config", func(t *testing.T) {
		cfg := &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		}
		listener, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
		if err != nil {
			t.Fatalf("tls.Listen: %v", err)
		}
		listener.Close()
	})

	t.Run("uniqueness", func(t *testing.T) {
		other, err := serve.GenerateSelfSignedCert()
		if err != nil {
			t.Fatal(err)
		}
		otherLeaf, err := x509.ParseCertificate(other.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		if leaf.SerialNumber.Cmp(otherLeaf.SerialNumber) == 0 {
			t.Error("two certs have identical serial numbers")
		}
	})
}
