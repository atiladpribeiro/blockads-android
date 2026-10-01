package mitm

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCertManagerRefusesToReplaceTrustedCA(t *testing.T) {
	dir := t.TempDir()
	first, err := NewCertManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	original := first.GetCACertPEM()
	block, _ := pem.Decode([]byte(original))
	if block == nil {
		t.Fatal("generated CA is not PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.Subject.CommonName != "Local Filtering CA" {
		t.Fatalf("unexpected CA owner: %s", certificate.Subject.CommonName)
	}

	keyPath := filepath.Join(dir, CAKeyFile)
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Fatalf("private key mode is %o, expected 600", keyInfo.Mode().Perm())
	}
	if err := os.WriteFile(keyPath, []byte("invalid key"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCertManager(dir); err == nil {
		t.Fatal("invalid private key unexpectedly caused a replacement CA")
	}
	cert, err := os.ReadFile(filepath.Join(dir, CACertFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(cert) != original {
		t.Fatal("trusted public certificate was replaced")
	}

	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCertManager(dir); err == nil {
		t.Fatal("missing private key unexpectedly caused a replacement CA")
	}
}
