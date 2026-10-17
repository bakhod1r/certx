package apache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bakhod1r/certx/internal/webserver"
)

var paths = webserver.CertPaths{Cert: "/var/lib/certx/certs/a.example/fullchain.pem", Key: "/var/lib/certx/certs/a.example/privkey.pem"}

func TestEditTLSExistingSSLVhost(t *testing.T) {
	src := `<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName a.example
    SSLEngine on
    SSLCertificateFile /old/cert.pem
    SSLCertificateChainFile /old/chain.pem
</VirtualHost>
</IfModule>
`
	vh := webserver.VirtualHost{Line: 2, Listen: []webserver.Listen{{Port: 443, TLS: true}}}
	p, err := (&Adapter{}).EditTLS([]byte(src), vh, paths, webserver.TLSOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := `<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName a.example
    SSLEngine on
    SSLCertificateFile /var/lib/certx/certs/a.example/fullchain.pem
    SSLCertificateKeyFile /var/lib/certx/certs/a.example/privkey.pem
    # SSLCertificateChainFile /old/chain.pem
</VirtualHost>
</IfModule>
`
	if string(p.After) != want {
		t.Errorf("got:\n%s", p.After)
	}
}

func TestEditTLSCreatesSSLVhost(t *testing.T) {
	root := t.TempDir()
	avail := filepath.Join(root, "sites-available")
	enabled := filepath.Join(root, "sites-enabled")
	for _, d := range []string{avail, enabled, filepath.Join(root, "mods-enabled")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	src := `<VirtualHost *:80>
    ServerName a.example
    ProxyPass / http://127.0.0.1:8080/
    RewriteEngine on
    RewriteCond %{SERVER_NAME} =a.example
    RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>
`
	file := filepath.Join(avail, "a.conf")
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	vh := webserver.VirtualHost{File: file, Line: 1, Names: []string{"a.example"}, Listen: []webserver.Listen{{Addr: "*", Port: 80}}, RedirectsToHTTPS: true}
	p, err := (&Adapter{}).EditTLS([]byte(src), vh, paths, webserver.TLSOptions{Redirect: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Extra) != 2 {
		t.Fatalf("extra = %+v", p.Extra)
	}
	ssl := string(p.Extra[0].After)
	for _, s := range []string{"<VirtualHost *:443>", "ProxyPass / http://127.0.0.1:8080/", "SSLEngine on", "SSLCertificateFile " + paths.Cert, "</IfModule>"} {
		if !strings.Contains(ssl, s) {
			t.Errorf("ssl vhost missing %q:\n%s", s, ssl)
		}
	}
	if strings.Contains(ssl, "RewriteRule") || strings.Contains(ssl, "RewriteCond") {
		t.Errorf("https redirect copied into SSL vhost:\n%s", ssl)
	}
	if p.Extra[1].Symlink != "../sites-available/a-certx-ssl.conf" || p.Extra[1].Path != filepath.Join(enabled, "a-certx-ssl.conf") {
		t.Errorf("symlink = %+v", p.Extra[1])
	}
	if len(p.Notes) != 1 || !strings.Contains(p.Notes[0], "a2enmod ssl") { // a2enmod rewrite only matters with Redirect
		t.Errorf("notes = %v", p.Notes)
	}
	if p.After != nil {
		t.Error("vhost with an existing https redirect must not get another one")
	}
	vh.RedirectsToHTTPS = false
	if p, _ := (&Adapter{}).EditTLS([]byte(src), vh, paths, webserver.TLSOptions{Redirect: true}); !strings.Contains(string(p.After), "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [END,NE,R=permanent]") {
		t.Errorf("redirect not added:\n%s", p.After)
	}

	// The generated file must parse back as a TLS vhost.
	ls := logicalLines(ssl)
	i := 0
	nodes, err := newParser(root, true).parseSection("x", ls, &i, "")
	if err != nil {
		t.Fatal(err)
	}
	var hosts []webserver.VirtualHost
	collect(nodes, root, true, &hosts)
	if len(hosts) != 1 || !hosts[0].TLS() || hosts[0].KeyFile != paths.Key {
		t.Errorf("re-parsed: %+v", hosts)
	}
}

func TestEditChallengeApache(t *testing.T) {
	src := "<VirtualHost *:80>\n\tServerName a.example\n\tProxyPass / http://127.0.0.1:9000/\n</VirtualHost>\n"
	p, err := (&Adapter{}).EditChallenge([]byte(src), webserver.VirtualHost{Line: 1}, "/var/lib/certx/acme-challenge")
	if err != nil {
		t.Fatal(err)
	}
	got := string(p.After)
	if !strings.Contains(got, "\tAlias /.well-known/acme-challenge/ \"/var/lib/certx/acme-challenge/.well-known/acme-challenge/\"\n") {
		t.Errorf("got:\n%s", got)
	}
	if strings.Index(got, "ProxyPass /.well-known/acme-challenge/ !") > strings.Index(got, "ProxyPass / http") {
		t.Errorf("challenge exclusion must precede ProxyPass /:\n%s", got)
	}
}
