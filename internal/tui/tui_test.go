package tui

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bakhod1r/certx/internal/discovery"
	"github.com/bakhod1r/certx/internal/state"
	"github.com/bakhod1r/certx/internal/webserver"
)

func press(m tea.Model, keys ...string) tea.Model {
	for _, k := range keys {
		var msg tea.KeyMsg
		switch k {
		case "enter":
			msg = tea.KeyMsg{Type: tea.KeyEnter}
		case "esc":
			msg = tea.KeyMsg{Type: tea.KeyEsc}
		case "tab":
			msg = tea.KeyMsg{Type: tea.KeyTab}
		default:
			msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
		}
		m, _ = m.Update(msg)
	}
	return m
}

func TestModelFlow(t *testing.T) {
	nginxConf, _ := filepath.Abs("../../tests/fixtures/nginx/nginx.conf")
	apacheConf, _ := filepath.Abs("../../tests/fixtures/apache-debian/apache2.conf")
	opts := discovery.Options{
		Servers:      []webserver.Kind{webserver.KindNginx, webserver.KindApache},
		NginxConfig:  nginxConf,
		ApacheConfig: apacheConf,
	}
	inv, err := discovery.Scan(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}

	var m tea.Model = newModel(Options{Scan: opts, Storage: "/var/lib/certx"})
	m, _ = m.Update(tea.WindowSizeMsg{Width: 140, Height: 30})
	if !strings.Contains(m.View(), "Scanning") {
		t.Fatal("expected loading screen")
	}
	m, _ = m.Update(scanDoneMsg{inv: inv, lastRun: &state.Run{Finished: time.Now().Add(-3 * time.Hour), Failed: 1}})

	out := m.View()
	for _, s := range []string{"CertX", "8 hosts", "✖ 1 failed 3h ago", "app.example.com", "blog.example.org", "[disabled]"} {
		if !strings.Contains(out, s) {
			t.Errorf("list view missing %q", s)
		}
	}

	// Apache tab hides Nginx hosts.
	m = press(m, "tab", "tab")
	if out = m.View(); strings.Contains(out, "app.example.com") || !strings.Contains(out, "blog.example.org") {
		t.Errorf("apache tab filter failed:\n%s", out)
	}

	// Filter, open details, go back.
	m = press(m, "tab", "/", "s", "h", "o", "p", "enter")
	if mm := m.(model); len(mm.rows) != 1 {
		t.Fatalf("filter rows = %d", len(mm.rows))
	}
	m = press(m, "enter")
	if out = m.View(); !strings.Contains(out, "/var/www/shop") || !strings.Contains(out, "Live TLS endpoint") {
		t.Errorf("detail view:\n%s", out)
	}
	m = press(m, "d")
	if out = m.View(); !strings.Contains(out, "+    listen 443 ssl; # managed by CertX") {
		t.Errorf("deploy plan view:\n%s", out)
	}
	m = press(m, "esc", "w")
	if !strings.Contains(m.View(), "Warnings") {
		t.Error("warnings view not shown")
	}
}
