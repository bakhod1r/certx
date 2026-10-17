package certificate_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/bakhod1r/certx/internal/certificate"
	"github.com/bakhod1r/certx/internal/certificate/certtest"
)

func TestInspectSelfSigned(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	cert, key := certtest.WritePair(t, dir, "a", []string{"example.com", "*.example.com"}, now, 90*24*time.Hour)
	_, otherKey := certtest.WritePair(t, dir, "b", []string{"example.com"}, now, time.Hour)

	info, err := certificate.Inspect(cert, key, now)
	if err != nil {
		t.Fatal(err)
	}
	if !info.SelfSigned || info.ChainLength != 1 || info.DaysLeft != 89 {
		t.Errorf("info = %+v", info)
	}
	if info.KeyMatch == nil || !*info.KeyMatch || info.KeyPermissive {
		t.Errorf("key match = %v permissive = %v", info.KeyMatch, info.KeyPermissive)
	}
	if !info.Covers("www.example.com") || info.Covers("example.org") {
		t.Error("Covers mismatch")
	}

	info, err = certificate.Inspect(cert, otherKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if info.KeyMatch == nil || *info.KeyMatch {
		t.Error("expected key mismatch")
	}

	if _, err := certificate.Inspect(filepath.Join(dir, "missing.pem"), "", now); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestWeakKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "weak.example"},
		DNSNames: []string{"weak.example"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	info, err := certificate.InspectPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if info.KeyAlgorithm != "RSA 1024" || len(info.Weak) != 1 {
		t.Errorf("alg=%s weak=%v", info.KeyAlgorithm, info.Weak)
	}
}
