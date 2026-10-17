package nginx

import (
	"strings"
	"testing"

	"github.com/bakhod1r/certx/internal/webserver"
)

var paths = webserver.CertPaths{Cert: "/var/lib/certx/certs/a.example/fullchain.pem", Key: "/var/lib/certx/certs/a.example/privkey.pem"}

func TestEditTLSAddsListenerToPlainBlock(t *testing.T) {
	src := `http {
    server {
        listen 80;
        listen [::]:80;
        server_name a.example;
        location / { proxy_pass http://127.0.0.1:8080; }
    }
}
`
	vh := webserver.VirtualHost{Line: 2, Listen: []webserver.Listen{{Port: 80}}}
	p, err := (&Adapter{}).EditTLS([]byte(src), vh, paths, webserver.TLSOptions{Redirect: true})
	if err != nil {
		t.Fatal(err)
	}
	want := `http {
    server {
        listen 80;
        listen [::]:80;
        server_name a.example;
        location / { proxy_pass http://127.0.0.1:8080; }
        listen 443 ssl; # managed by CertX
        listen [::]:443 ssl; # managed by CertX
        ssl_certificate /var/lib/certx/certs/a.example/fullchain.pem; # managed by CertX
        ssl_certificate_key /var/lib/certx/certs/a.example/privkey.pem; # managed by CertX
        if ($scheme != "https") { return 301 https://$host$request_uri; } # managed by CertX
    }
}
`
	if got := string(p.After); got != want {
		t.Errorf("got:\n%s", got)
	}
	// The result must still parse and expose a TLS listener.
	n, err := findServer(p.After, 2)
	if err != nil {
		t.Fatal(err)
	}
	if h := serverToHost(n, "/", inherited{}, true); !h.TLS() || h.CertFile != paths.Cert {
		t.Errorf("re-parsed host: %+v", h)
	}
}

func TestEditTLSReplacesExistingCertificate(t *testing.T) {
	src := "server { listen 443 ssl; server_name a.example; ssl_certificate /old/c.pem; ssl_certificate_key \"/old/k.pem\"; }\n"
	vh := webserver.VirtualHost{Line: 1, Listen: []webserver.Listen{{Port: 443, TLS: true}}}
	p, err := (&Adapter{}).EditTLS([]byte(src), vh, paths, webserver.TLSOptions{Redirect: true})
	if err != nil {
		t.Fatal(err)
	}
	want := "server { listen 443 ssl; server_name a.example; ssl_certificate " + paths.Cert + "; ssl_certificate_key " + paths.Key + "; }\n"
	if string(p.After) != want {
		t.Errorf("got:\n%s", p.After)
	}
	// Idempotent.
	p2, _ := (&Adapter{}).EditTLS(p.After, vh, paths, webserver.TLSOptions{})
	if string(p2.After) != want {
		t.Errorf("second edit changed the file:\n%s", p2.After)
	}
}

func TestEditTLSInlineBlock(t *testing.T) {
	src := "server { listen 80; server_name a.example; }\nserver { listen 80; server_name b.example; }\n"
	vh := webserver.VirtualHost{Line: 2, Listen: []webserver.Listen{{Port: 80}}}
	p, err := (&Adapter{}).EditTLS([]byte(src), vh, paths, webserver.TLSOptions{})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(p.After), "\n")
	if lines[0] != "server { listen 80; server_name a.example; }" {
		t.Errorf("first block changed: %s", lines[0])
	}
	if !strings.HasPrefix(lines[1], "server { listen 80; server_name b.example; listen 443 ssl; ssl_certificate ") || !strings.HasSuffix(lines[1], "; }") {
		t.Errorf("inline edit: %s", lines[1])
	}
}

func TestEditChallenge(t *testing.T) {
	src := "server {\n\tlisten 80;\n\treturn 301 https://$host$request_uri;\n}\n"
	p, err := (&Adapter{}).EditChallenge([]byte(src), webserver.VirtualHost{Line: 1}, "/var/lib/certx/acme-challenge")
	if err != nil {
		t.Fatal(err)
	}
	want := "server {\n\tlisten 80;\n\treturn 301 https://$host$request_uri;\n" +
		"\tlocation ^~ /.well-known/acme-challenge/ { root /var/lib/certx/acme-challenge; default_type \"text/plain\"; } # " +
		webserver.ChallengeMarker + "\n}\n"
	if string(p.After) != want {
		t.Errorf("got:\n%q\nwant:\n%q", p.After, want)
	}
}

func TestEditMissingBlock(t *testing.T) {
	if _, err := (&Adapter{}).EditTLS([]byte("server { }\n"), webserver.VirtualHost{Line: 7}, paths, webserver.TLSOptions{}); err == nil {
		t.Error("expected error for unknown line")
	}
}
