package plan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bakhod1r/certx/internal/discovery"
	"github.com/bakhod1r/certx/internal/webserver"
)

func TestActionsAndChanges(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	src := `events {}
http {
    server {
        listen 80;
        server_name a.example.com;
        return 301 https://$host$request_uri;
    }
    server {
        listen 443 ssl;
        server_name a.example.com;
        ssl_certificate /etc/letsencrypt/live/a.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/a.example.com/privkey.pem;
    }
    server {
        listen 80;
        server_name b.example.com;
    }
    server {
        listen 80;
        server_name c.example.com;
    }
    server {
        listen 80;
        server_name localhost;
    }
}
`
	if err := os.WriteFile(conf, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	inv, err := discovery.Scan(context.Background(), discovery.Options{Servers: []webserver.Kind{webserver.KindNginx}, NginxConfig: conf})
	if err != nil {
		t.Fatal(err)
	}

	acts := Actions(inv, Options{})
	if len(acts) != 3 {
		t.Fatalf("actions = %d: %+v", len(acts), acts)
	}
	if acts[0].Names[0] != "a.example.com" || acts[0].Skip == "" {
		t.Errorf("certbot host should be skipped: %+v", acts[0])
	}
	if !acts[1].NeedCert || acts[1].Skip != "" {
		t.Errorf("b should need a cert: %+v", acts[1])
	}
	if a := Actions(inv, Options{Force: true}); a[0].Skip != "" {
		t.Error("--force should take over certbot hosts")
	}
	if a := Actions(inv, Options{Domains: []string{"C.example.com"}}); len(a) != 1 || a[0].Names[0] != "c.example.com" {
		t.Errorf("domain filter: %+v", a)
	}

	// Edit two blocks in the same file; bottom-up order keeps both correct.
	c := webserver.CertPaths{Cert: "/x/fullchain.pem", Key: "/x/privkey.pem"}
	cs, err := Changes(inv, "test", []discovery.Host{acts[1].Host, acts[2].Host}, TLS(c, webserver.TLSOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.Edits) != 1 || len(cs.Servers) != 1 {
		t.Fatalf("change set: %+v", cs)
	}
	after := string(cs.Edits[0].After)
	if strings.Count(after, "ssl_certificate /x/fullchain.pem; # managed by CertX") != 2 {
		t.Errorf("after:\n%s", after)
	}

	// Challenge targets include the redirecting HTTP block and the TLS block.
	if s := Serving(inv, []string{"a.example.com"}); len(s) != 2 {
		t.Errorf("serving = %d", len(s))
	}
}

func TestFilterAndCovers(t *testing.T) {
	f := Filter{Exclude: []string{"*.internal", "staging.*"}}
	for name, want := range map[string]bool{"a.example.com": true, "db.internal": false, "staging.example.com": false} {
		if f.Permits(name) != want {
			t.Errorf("Permits(%q) != %v", name, want)
		}
	}
	allow := Filter{Allow: []string{"*.example.com"}}
	if !allow.Permits("www.example.com") || allow.Permits("example.org") {
		t.Error("allowlist")
	}
	for _, c := range []struct {
		pattern, name string
		want          bool
	}{{"*.example.com", "www.example.com", true}, {"*.example.com", "a.b.example.com", false}, {"*.example.com", "example.com", false}, {"example.com", "example.com", false}} {
		if Covers(c.pattern, c.name) != c.want {
			t.Errorf("Covers(%q, %q) != %v", c.pattern, c.name, c.want)
		}
	}
}
