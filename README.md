# CertX

Go-based SSL/TLS certificate automation for **Nginx** and **Apache**.
CertX discovers virtual hosts from web server configuration, audits the
certificates they use and (in upcoming milestones) issues and renews
Let's Encrypt certificates.

See [docs/PLAN.md](docs/PLAN.md) for the architecture plan and roadmap.

## Status

Implemented (P0.1–P0.3):

- Nginx adapter: `nginx.conf` parser with recursive `include` globs, symlinks,
  `sites-available` detection of disabled sites, http-level certificate inheritance.
- Apache adapter: Debian (`apache2`) and RHEL (`httpd`) layouts, `Include` /
  `IncludeOptional`, `<VirtualHost>` inside `<IfModule>`, line continuations.
- Certificate audit: expiry, hostname coverage, self-signed, chain trust,
  certificate/key match, private-key permissions, duplicate server names.
- Live TLS check: compares the certificate served by the endpoint with the local file.
- Interactive terminal UI and a scriptable `scan` command.

## Install

```sh
go install github.com/bakhod1r/certx/cmd/certx@latest
```

## Usage

```sh
sudo certx                         # interactive TUI (auto-detects Nginx and Apache)
sudo certx scan                    # table output, exit code 2 on critical problems
sudo certx scan --json             # machine-readable inventory
sudo certx validate                # nginx -t / apachectl -t
certx --server nginx --nginx-conf /etc/nginx/nginx.conf
```

Try it without a web server installed:

```sh
go run ./cmd/certx --nginx-conf tests/fixtures/nginx/nginx.conf \
                   --apache-conf tests/fixtures/apache-debian/apache2.conf
```

### TUI keys

| Key | Action |
|---|---|
| `↑/↓`, `j/k`, `pgup/pgdn`, `g/G` | Move |
| `enter` | Host and certificate details |
| `t` (in details) | Fetch the certificate served over TLS and compare |
| `n` / `p` (in details) | Next / previous host |
| `tab` / `shift+tab` | All / Nginx / Apache |
| `/` | Filter by domain or file (`esc` clears) |
| `s` | Sort: severity, expiry, domain, file |
| `r` | Rescan |
| `v` | Run `nginx -t` / `apachectl -t` |
| `e` | Export inventory as JSON |
| `w` | Show parser warnings |
| `?` | Help |
| `q` | Quit |

### Flags and environment

| Flag | Environment | Default |
|---|---|---|
| `--server` | `CERTX_SERVER` | `auto` |
| `--nginx-conf` | `CERTX_NGINX_CONF` | auto-detected |
| `--apache-conf` | `CERTX_APACHE_CONF` | auto-detected |
| `--apache-root` | `CERTX_APACHE_ROOT` | derived from config path |
| `--warn-days` | `CERTX_WARN_DAYS` | `30` |
| `--json` | | `false` |

### Statuses

`OK`, `NO TLS`, `SELF-SIGNED`, `EXPIRING`, `BAD CHAIN`, `MISMATCH`,
`NOT YET VALID`, `KEY MISMATCH`, `EXPIRED`, `ERROR` (ordered by severity).
`scan` exits with code `2` when an enabled host is `MISMATCH` or worse.

## Development

```sh
go test ./...
go vet ./...
```
