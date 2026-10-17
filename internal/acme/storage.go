package acme

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	Email     string    `json:"email,omitempty"`
	DNS       string    `json:"dns_provider,omitempty"` // DNS-01 provider; empty means HTTP-01
	Serial    string    `json:"serial"`
	IssuedAt  time.Time `json:"issued_at"`
	NotAfter  time.Time `json:"not_after"`

	RevokedSerial string    `json:"revoked_serial,omitempty"`
	RevokedAt     time.Time `json:"revoked_at,omitzero"`
}

// SaveMeta rewrites the metadata of a stored certificate.
func SaveMeta(storage, name string, m *Meta) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return deployment.AtomicWrite(filepath.Join(storage, "certs", name, "meta.json"), append(data, '\n'), 0o644)
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

// List returns the names of all stored certificates.
func List(storage string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(storage, "certs", "*", "meta.json"))
	if err != nil {
		return nil, err
	}
	var names []string
	for _, m := range matches {
		names = append(names, filepath.Base(filepath.Dir(m)))
	}
	return names, nil
}

// Find returns the stored certificate for domain: the one named after it,
// otherwise the first one whose domains include it.
func Find(storage, domain string) (string, *Meta, error) {
	if name, err := CertName(domain); err == nil {
		if m, err := LoadMeta(storage, name); err == nil {
			return name, m, nil
		}
	}
	names, err := List(storage)
	if err != nil {
		return "", nil, err
	}
	sort.Strings(names)
	for _, n := range names {
		m, err := LoadMeta(storage, n)
		if err != nil {
			continue
		}
		for _, d := range m.Domains {
			if strings.EqualFold(d, domain) {
				return n, m, nil
			}
		}
	}
	return "", nil, fmt.Errorf("no CertX certificate for %s (run certx issue first)", domain)
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
