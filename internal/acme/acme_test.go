package acme

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirectoryURL(t *testing.T) {
	for in, want := range map[string]string{"": LetsEncryptStaging, "staging": LetsEncryptStaging, "production": LetsEncryptProduction, "https://ca.example/dir": "https://ca.example/dir"} {
		if got, err := DirectoryURL(in); err != nil || got != want {
			t.Errorf("DirectoryURL(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"http://ca.example/dir", "nonsense"} {
		if _, err := DirectoryURL(bad); err == nil {
			t.Errorf("DirectoryURL(%q) accepted", bad)
		}
	}
}

func TestCertName(t *testing.T) {
	if n, err := CertName("WWW.Example.com."); err != nil || n != "www.example.com" {
		t.Errorf("got %q, %v", n, err)
	}
	for _, bad := range []string{"../etc", "a/b", "", "-x.com"} {
		if _, err := CertName(bad); err == nil {
			t.Errorf("CertName(%q) accepted", bad)
		}
	}
}

func TestSaveAndAccount(t *testing.T) {
	dir := t.TempDir()
	b := &Bundle{Leaf: []byte("leaf"), Chain: []byte("chain"), FullChain: []byte("leafchain"), PrivateKey: []byte("key")}
	paths, err := Save(dir, "a.example", b, Meta{Domains: []string{"a.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(paths.Key); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("key mode: %v %v", fi, err)
	}
	if m, err := LoadMeta(dir, "a.example"); err != nil || m.Domains[0] != "a.example" {
		t.Errorf("meta: %+v %v", m, err)
	}

	a, err := loadAccount(dir, LetsEncryptStaging, "ops@example.com")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "accounts", "acme-staging-v02.api.letsencrypt.org", "ops@example.com", "key.pem")
	if fi, err := os.Stat(keyFile); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("account key: %v %v", fi, err)
	}
	again, err := loadAccount(dir, LetsEncryptStaging, "ops@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !a.key.(*ecdsa.PrivateKey).Equal(again.key) {
		t.Error("account key not reused")
	}
	if _, err := loadAccount(dir, LetsEncryptStaging, "../evil"); err == nil {
		t.Error("path traversal in email accepted")
	}
}

func TestSelfTest(t *testing.T) {
	root := t.TempDir()
	srv := httptest.NewServer(http.FileServer(http.Dir(root)))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	if err := SelfTest(context.Background(), root, []string{"a.example:" + port}, host); err != nil {
		t.Fatalf("self-test against a serving webroot failed: %v", err)
	}
	settle = 0
	if err := SelfTest(context.Background(), t.TempDir(), []string{"a.example:" + port}, host); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("expected 404 failure, got %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(root, ".well-known", "acme-challenge")); len(entries) != 0 {
		t.Error("token not cleaned up")
	}
}

func TestFind(t *testing.T) {
	dir := t.TempDir()
	b := &Bundle{Leaf: []byte("l"), Chain: []byte("c"), FullChain: []byte("lc"), PrivateKey: []byte("k")}
	if _, err := Save(dir, "_wildcard.example.com", b, Meta{Domains: []string{"*.example.com", "example.com"}}); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"*.example.com", "EXAMPLE.com"} {
		if n, _, err := Find(dir, d); err != nil || n != "_wildcard.example.com" {
			t.Errorf("Find(%q) = %q, %v", d, n, err)
		}
	}
	if _, _, err := Find(dir, "other.example.com"); err == nil {
		t.Error("found a certificate that does not include the domain")
	}
}

func TestExplainNil(t *testing.T) {
	if explain(nil) != nil {
		t.Fatal("explain(nil) must be nil")
	}
	if err := explain(errors.New("urn:ietf:params:acme:error:rateLimited")); !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("err = %v", err)
	}
}
