package acme

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bakhod1r/certx/internal/deployment"
	"github.com/bakhod1r/certx/internal/webserver"
)

// DefaultStorage is the root of CertX state.
const DefaultStorage = "/var/lib/certx"

var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)

// Meta is stored next to every certificate.
type Meta struct {
	Domains   []string  `json:"domains"`
	Directory string    `json:"directory"`
	Serial    string    `json:"serial"`
	IssuedAt  time.Time `json:"issued_at"`
	NotAfter  time.Time `json:"not_after"`
}

// CertName derives the storage directory name from the primary domain.
func CertName(domain string) (string, error) {
	n := strings.ToLower(strings.TrimSuffix(domain, "."))
	n = strings.Replace(n, "*.", "_wildcard.", 1)
	if !nameRe.MatchString(strings.TrimPrefix(n, "_wildcard.")) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	return n, nil
}

// Paths returns where the certificate named name is stored.
func Paths(storage, name string) webserver.CertPaths {
	dir := filepath.Join(storage, "certs", name)
	return webserver.CertPaths{Cert: filepath.Join(dir, "fullchain.pem"), Key: filepath.Join(dir, "privkey.pem")}
}

// Save writes a certificate bundle. The private key is written with 0600.
func Save(storage, name string, b *Bundle, meta Meta) (webserver.CertPaths, error) {
	paths := Paths(storage, name)
	dir := filepath.Dir(paths.Cert)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return paths, err
	}
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"privkey.pem", b.PrivateKey, 0o600},
		{"cert.pem", b.Leaf, 0o644},
		{"chain.pem", b.Chain, 0o644},
		{"fullchain.pem", b.FullChain, 0o644},
	}
	for _, f := range files {
		if err := deployment.AtomicWrite(filepath.Join(dir, f.name), f.data, f.mode); err != nil {
			return paths, err
		}
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return paths, err
	}
	return paths, deployment.AtomicWrite(filepath.Join(dir, "meta.json"), append(data, '\n'), 0o644)
}

// LoadMeta reads the metadata of a stored certificate.
func LoadMeta(storage, name string) (*Meta, error) {
	data, err := os.ReadFile(filepath.Join(storage, "certs", name, "meta.json"))
	if err != nil {
		return nil, err
	}
	var m Meta
	return &m, json.Unmarshal(data, &m)
}
