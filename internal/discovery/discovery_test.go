package discovery

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bakhod1r/certx/internal/certificate/certtest"
	"github.com/bakhod1r/certx/internal/webserver"
)

func TestScanStatuses(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	okCert, okKey := certtest.WritePair(t, dir, "ok", []string{"ok.example.com"}, now, 90*24*time.Hour)
	soonCert, soonKey := certtest.WritePair(t, dir, "soon", []string{"soon.example.com"}, now, 5*24*time.Hour)
	oldCert, oldKey := certtest.WritePair(t, dir, "old", []string{"old.example.com"}, now.AddDate(0, 0, -100), 90*24*time.Hour)
	_, otherKey := certtest.WritePair(t, dir, "other", []string{"x.example.com"}, now, time.Hour)

	server := func(name, cert, key string) string {
		return fmt.Sprintf("server { listen 443 ssl; server_name %s; ssl_certificate %s; ssl_certificate_key %s; }\n", name, cert, key)
	}
	conf := "events {}\nhttp {\n" +
		server("ok.example.com", okCert, okKey) +
		server("soon.example.com", soonCert, soonKey) +
		server("old.example.com", oldCert, oldKey) +
		server("wrong.example.com", okCert, okKey) +
		server("key.example.com", okCert, otherKey) +
		server("gone.example.com", filepath.Join(dir, "missing.crt"), okKey) +
		"server { listen 80; server_name plain.example.com; }\n" +
		"server { listen 80; server_name plain.example.com; }\n" +
		"}\n"
	path := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}

	inv, err := Scan(context.Background(), Options{
		Servers:     []webserver.Kind{webserver.KindNginx},
		NginxConfig: path,
		Now:         func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []Status{
		StatusSelfSigned, // self-signed but otherwise fine
		StatusExpiring,
		StatusExpired,
		StatusMismatch,
		StatusKeyMismatch,
		StatusError,
		StatusNoTLS,
		StatusNoTLS,
	}
	if len(inv.Hosts) != len(want) {
		t.Fatalf("got %d hosts", len(inv.Hosts))
	}
	for i, h := range inv.Hosts {
		if h.Status != want[i] {
			t.Errorf("%s: status %s, want %s (issues %v)", h.Names[0], h.Status, want[i], h.Issues)
		}
	}
	if last := inv.Hosts[7]; !strings.Contains(strings.Join(last.Issues, ";"), "duplicate server name") {
		t.Errorf("duplicate not reported: %v", last.Issues)
	}
	if !StatusExpired.Critical() || StatusExpiring.Critical() {
		t.Error("Critical() thresholds changed")
	}
}

func TestCheckable(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM": "example.com", ".example.com": "example.com", "_": "", "localhost": "",
		"10.0.0.1": "", "~^www": "", "intranet": "", "db.internal": "",
	} {
		if got := checkable(in); got != want {
			t.Errorf("checkable(%q) = %q, want %q", in, got, want)
		}
	}
}
