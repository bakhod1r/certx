package nginx

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/bakhod1r/certx/internal/webserver"
)

func TestDiscoverFixture(t *testing.T) {
	conf, _ := filepath.Abs("../../../tests/fixtures/nginx/nginx.conf")
	a := &Adapter{ConfigPath: conf}
	res, err := a.Discover(context.Background(), webserver.Installation{ConfigPath: conf})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", res.Warnings)
	}
	if len(res.Hosts) != 4 {
		t.Fatalf("want 4 hosts, got %d: %+v", len(res.Hosts), res.Hosts)
	}

	redirect, tls, shop, legacy := res.Hosts[0], res.Hosts[1], res.Hosts[2], res.Hosts[3]

	if !redirect.RedirectsToHTTPS || redirect.TLS() || redirect.Ports() != "80" {
		t.Errorf("redirect host: %+v", redirect)
	}
	if !tls.TLS() || tls.Ports() != "443s" || tls.ManagedBy != "certbot" {
		t.Errorf("tls host: %+v", tls)
	}
	if tls.CertFile != "/etc/letsencrypt/live/app.example.com/fullchain.pem" {
		t.Errorf("cert file = %q", tls.CertFile)
	}
	if want := []string{"app.example.com", "api.example.com"}; !reflect.DeepEqual(tls.Names, want) {
		t.Errorf("names = %v", tls.Names)
	}
	if shop.Names[1] != `~^(?<sub>.+)\.shop\.example\.com$` {
		t.Errorf("regex name = %q", shop.Names[1])
	}
	if !shop.Enabled || shop.Webroot != "/var/www/shop" || len(shop.Names) != 2 {
		t.Errorf("shop host: %+v", shop)
	}
	if legacy.Enabled || legacy.Names[0] != "old.example.com" {
		t.Errorf("legacy host should be disabled: %+v", legacy)
	}
}

func TestParseListen(t *testing.T) {
	cases := []struct {
		args []string
		want webserver.Listen
	}{
		{[]string{"443", "ssl"}, webserver.Listen{Port: 443, TLS: true}},
		{[]string{"[::]:443", "ssl", "http2"}, webserver.Listen{Addr: "[::]", Port: 443, TLS: true}},
		{[]string{"127.0.0.1:8080"}, webserver.Listen{Addr: "127.0.0.1", Port: 8080}},
		{[]string{"localhost"}, webserver.Listen{Addr: "localhost", Port: 80}},
	}
	for _, c := range cases {
		if got := parseListen(c.args); got != c.want {
			t.Errorf("parseListen(%v) = %+v, want %+v", c.args, got, c.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, src := range []string{"server {", "server { listen 80 }", "}"} {
		p := newParser("/")
		toks := tokenize(src)
		i := 0
		if _, err := p.parseBlock("test.conf", toks, &i, false); err == nil {
			t.Errorf("expected error for %q", src)
		}
	}
}
