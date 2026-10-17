package apache

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bakhod1r/certx/internal/webserver"
)

func discover(t *testing.T, conf string) *webserver.Result {
	t.Helper()
	conf, _ = filepath.Abs(conf)
	a := &Adapter{ConfigPath: conf}
	res, err := a.Discover(context.Background(), webserver.Installation{ConfigPath: conf})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestDiscoverDebian(t *testing.T) {
	res := discover(t, "../../../tests/fixtures/apache-debian/apache2.conf")

	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "options-ssl-apache.conf") {
		t.Errorf("warnings = %v", res.Warnings)
	}
	if len(res.Hosts) != 4 {
		t.Fatalf("want 4 hosts, got %d: %+v", len(res.Hosts), res.Hosts)
	}
	// Glob order: 000-default, blog-le-ssl, blog, then disabled sites.
	def, blogSSL, blog, old := res.Hosts[0], res.Hosts[1], res.Hosts[2], res.Hosts[3]

	if len(def.Names) != 0 || def.Ports() != "80" {
		t.Errorf("default host: %+v", def)
	}
	if !blog.RedirectsToHTTPS || blog.TLS() {
		t.Errorf("blog: %+v", blog)
	}
	if want := []string{"blog.example.org", "www.blog.example.org"}; !reflect.DeepEqual(blogSSL.Names, want) {
		t.Errorf("names = %v", blogSSL.Names)
	}
	if !blogSSL.TLS() || blogSSL.Ports() != "443s" || blogSSL.Webroot != "/var/www/blog" || blogSSL.ManagedBy != "certbot" {
		t.Errorf("blog ssl: %+v", blogSSL)
	}
	if old.Enabled {
		t.Errorf("old-site should be disabled")
	}
}

func TestDiscoverRHEL(t *testing.T) {
	res := discover(t, "../../../tests/fixtures/apache-rhel/conf/httpd.conf")
	if len(res.Hosts) != 1 {
		t.Fatalf("want 1 host, got %+v", res.Hosts)
	}
	h := res.Hosts[0]
	if h.Names[0] != "intranet.example.net" || !h.TLS() || h.Listen[0].Addr != "_default_" {
		t.Errorf("host: %+v", h)
	}
}

func TestSplitArgs(t *testing.T) {
	got := splitArgs(`Header set X "a b" 'c d' e\f`)
	want := []string{"Header", "set", "X", "a b", "c d", `e\f`}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q", got)
	}
}

func TestContinuationAndErrors(t *testing.T) {
	ls := logicalLines("ServerAlias a.example \\\n   b.example\n# comment\n")
	if len(ls) != 1 || ls[0].text != "ServerAlias a.example b.example" {
		t.Errorf("lines = %+v", ls)
	}
	p := newParser("/", true)
	i := 0
	if _, err := p.parseSection("x", logicalLines("<VirtualHost *:80>\n"), &i, ""); err == nil {
		t.Error("expected missing close error")
	}
}
