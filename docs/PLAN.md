# CertX — Nginx va Apache uchun arxitektura rejasi

CertX yadrosi (discovery, audit, ACME, renewal, state) web serverga bog'liq emas.
Nginx va Apache bitta `webserver.Adapter` interfeysini amalga oshiruvchi adapterlar sifatida ulanadi.

## 1. Arxitektura

```
CLI (Cobra) / Scheduler (cron, systemd)
        │
Application services: Discovery · Audit · ACME · Renewal · Deploy · Rollback
        │
   webserver.Adapter
   ├── nginx adapter
   └── apache adapter (Debian apache2 + RHEL httpd)
        │
ACME (lego) · DNS preflight · State store (bbolt) · Notifications
```

## 2. Asosiy abstraksiya: `internal/webserver`

```go
package webserver

type Kind string

const (
	KindNginx  Kind = "nginx"
	KindApache Kind = "apache"
)

// Adapter is implemented by every supported web server.
type Adapter interface {
	Kind() Kind
	Detect(ctx context.Context) (*Installation, error)
	Discover(ctx context.Context) (*Inventory, error)
	Validate(ctx context.Context) error // nginx -t / apachectl -t
	Reload(ctx context.Context) error   // graceful reload
	PlanTLS(vh VirtualHost, c CertPaths, o TLSOptions) (*ChangeSet, error)
	ApplyChallenge(ctx context.Context, webroot string) (Cleanup, error)
}

type Installation struct {
	Binary, Version, ConfigRoot string
	Layout                      Layout   // debian, rhel, custom
	ServiceManager              string   // systemd, sysvinit, none
	Modules                     []string // apache: ssl_module, rewrite_module
}

// VirtualHost is a server-neutral view of a server block or <VirtualHost>.
type VirtualHost struct {
	ID        string
	Server    Kind
	File      string
	Line      int
	Enabled   bool
	Listen    []Listen
	Names     []string // server_name | ServerName + ServerAlias
	CertFile  string
	KeyFile   string
	ChainFile string // apache < 2.4.8 SSLCertificateChainFile
	Webroot   string // root | DocumentRoot
	ManagedBy string // certx, certbot, manual
}

// ChangeSet is a reversible, diffable set of file edits.
type ChangeSet struct {
	Edits []FileEdit
}
```

`ChangeSet` — `plan`, `deploy`, `--dry-run` va `rollback` uchun yagona asos.

## 3. Nginx va Apache farqlari

| Vazifa | Nginx | Apache |
|---|---|---|
| Binary | `nginx` | `apache2ctl`/`apachectl`, `httpd` |
| Config dump | `nginx -T` | `apachectl -t -D DUMP_INCLUDES`, `-S` |
| Parser | `nginx-go-crossplane` | O'z parserimiz (`<Section>`, `Include`/`IncludeOptional`, `\` davomi) |
| Domenlar | `server_name` | `ServerName` + `ServerAlias` |
| Sertifikat | `ssl_certificate(_key)` | `SSLCertificateFile`, `SSLCertificateKeyFile`, `SSLCertificateChainFile` |
| Yoqilgan saytlar | `sites-enabled` | Debian: `a2ensite`; RHEL: `conf.d/*.conf` |
| Modullar | — | `mod_ssl`, `mod_rewrite` |
| Validatsiya | `nginx -t` | `apachectl configtest` |
| Reload | `nginx -s reload` | `apachectl graceful` |
| HTTP-01 | `location ^~ /.well-known/acme-challenge/` | `Alias /.well-known/acme-challenge/ ...` |
| Redirect | `return 301 https://$host$request_uri;` | `Redirect permanent /` / `RewriteRule` |
| TLS vhost | shu blokda `listen 443 ssl` | alohida `<VirtualHost *:443>` |

Apache uchun CertX alohida `certx-<site>-ssl.conf` yaratadi — mavjud fayllar minimal o'zgaradi.

## 4. Paketlar tuzilmasi

```
certx/
├── cmd/certx/
├── internal/
│   ├── webserver/{nginx,apache}/
│   ├── discovery/  certificate/  audit/  acme/  dns/
│   ├── renewal/  deployment/  rollback/  scheduler/  state/
│   ├── notification/  security/  execx/  config/
├── tests/
│   ├── fixtures/{nginx,apache-debian,apache-rhel}/
│   └── e2e/   # Docker + Pebble ACME
```

## 5. Dizayn qoidalari

1. Ikkala server bir vaqtda bo'lishi mumkin (Nginx :443 proxy, Apache :8080 backend). Public 443 egasi `ss -ltnp` orqali aniqlanadi va deploy o'sha adapter orqali bo'ladi.
2. `server: auto | nginx | apache`. `auto` rejimida ikkalasi ham 80/443 da bo'lsa — aniq tanlash talab qilinadi.
3. Certbot boshqaradigan sertifikatlar (`/etc/letsencrypt/renewal`, `# managed by Certbot`) `--force`siz o'zgartirilmaydi.
4. Saqlash: `/var/lib/certx/certs/<name>/{fullchain,privkey,chain}.pem`, kalitlar `0600`.
5. Deploy: `plan → backup → atomic write → Validate → Reload → TLS verify → (xato) rollback`.
6. HTTP-01: avval webroot, bo'lmasa vaqtinchalik snippet; standalone faqat 80-port bo'sh bo'lsa.

## 6. Konfiguratsiya namunasi

```yaml
server: auto
nginx:
  binary: /usr/sbin/nginx
  config: /etc/nginx/nginx.conf
apache:
  binary: /usr/sbin/apache2ctl
  config: /etc/apache2/apache2.conf
  layout: auto
acme:
  directory: staging
  email: admin@example.com
  challenge: http-01
storage: /var/lib/certx
renewal:
  window_days: 30
domains:
  exclude: ["*.internal", "localhost"]
```

## 7. Yo'l xaritasi

| Bosqich | Natija |
|---|---|
| P0.1 | Adapter interfeysi, `execx`, `config`, Nginx adapteri, `scan` |
| P0.2 | Apache adapteri (Debian/RHEL), parser + `-S` cross-check |
| P0.3 | `status`, `inspect` (local va remote) |
| P0.4 | `ChangeSet` + `plan --dry-run` |
| P0.5 | lego, HTTP-01, `issue`, `validate` |
| P1 | `deploy`, `renew`, lock, backoff, cron/systemd, notifications |
| P2 | `rollback`, DNS/CAA preflight, Certbot bilan birga ishlash, `doctor` |
| P3 | DNS-01 provayderlar, wildcard, Prometheus |

## 8. Testlar

- Golden testlar (`fixtures/*`), round-trip parse/render.
- E2E: `nginx:stable`, `debian+apache2`, `rockylinux+httpd` + Pebble.
- Apache lexer uchun `go test -fuzz`.

**Asosiy xavf:** Apache parseri (`<IfModule>`, `Define`/`${VAR}`, glob `Include`). Natija har doim `apachectl -S` bilan solishtiriladi; mos kelmasa — faqat audit rejimi, deploy yo'q.
