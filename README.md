# CertX

Go-based SSL/TLS certificate automation for **Nginx** and **Apache**.
CertX discovers virtual hosts from web server configuration, audits the
certificates they use and (in upcoming milestones) issues and renews
Let's Encrypt certificates.

See [docs/PLAN.md](docs/PLAN.md) for the architecture plan and roadmap.

## Status

Implemented (P0):

- **Discovery** — Nginx (`include` globs, symlinks, disabled `sites-available`,
  http-level certificate inheritance) and Apache (Debian `apache2`, RHEL `httpd`,
  `Include`/`IncludeOptional`, `<VirtualHost>` inside `<IfModule>`).
- **Audit** — expiry, SAN coverage, self-signed, chain trust, certificate/key
  match, private-key permissions, duplicate server names, live TLS comparison.
- **Plan** — per-site recommendation plus the exact configuration diff a deploy would make.
- **Issue** — Let's Encrypt (staging by default) or any ACME CA over HTTP-01 via
  [lego](https://github.com/go-acme/lego), with a temporary challenge snippet
  and a local self-check before the CA is contacted.
- **Deploy** — edits only the affected server block / vhost, then
  backup → `nginx -t` / `apachectl -t` → graceful reload → HTTPS verification;
  any failure restores the backup automatically.
- **Rollback** — every change is recorded and can be undone.
- **Renew** — renews CertX certificates inside the renewal window, reuses the
  issuing CA and account, retries transient failures with backoff, reloads the
  servers using the certificate and verifies what HTTPS serves. Idempotent and
  locked against concurrent runs.
- **Scheduler** — twice-daily systemd timer (randomised, persistent) or cron job.
- **Alerts** — webhook (Slack/Mattermost compatible), Telegram and email for
  failed renewals and for any certificate on the server expiring soon
  (including Certbot or manually managed ones).
- **Logs** — rotated log file, JSON audit trail of issue/renew/deploy/rollback,
  last-run state shown by `certx scheduler status` and the TUI.
- **TUI** and scriptable commands with JSON output and CI exit codes.

## Install

```sh
go install github.com/bakhod1r/certx/cmd/certx@latest
```

## Usage

```sh
sudo certx                                    # interactive TUI
sudo certx scan [--json]                      # inventory; exit code 2 on critical problems
sudo certx plan                               # what needs a certificate and the config diff
sudo certx issue --domain example.com --domain www.example.com \
                 --email ops@example.com      # staging certificate (safe to test)
sudo certx issue --domain example.com --acme production --deploy --redirect
sudo certx deploy --domain example.com --dry-run
sudo certx rollback --list
sudo certx rollback <id>
sudo certx validate                           # nginx -t / apachectl -t
sudo certx renew --dry-run                    # what would be renewed
sudo certx scheduler install                  # systemd timer (or cron) running `certx renew`
sudo certx scheduler status                   # next run, last run, Certbot timers
sudo certx notify                             # send a test alert
```

### Automatic renewal

```sh
sudo certx scheduler install            # auto-detects systemd, falls back to cron
sudo certx scheduler install --scheduler cron --window-days 21
```

The job runs `certx renew --yes` twice a day with any explicitly given flags
(`--server`, `--nginx-conf`, `--storage`, `--window-days`, …). A certificate
is renewed when it expires within `--window-days` (30); the run exits non-zero
when a renewal fails, so systemd marks the unit failed.

### Settings, secrets and alerts

Put secrets in `/etc/certx/env` (`KEY=VALUE`, `chmod 600`); it is read by
interactive runs, cron and systemd alike, and real environment variables win:

```sh
CERTX_EMAIL=ops@example.com
CERTX_ACME=production
CERTX_WEBHOOK_URL=https://hooks.slack.com/services/...
CERTX_TELEGRAM_TOKEN=123456:ABC...
CERTX_TELEGRAM_CHAT_ID=-100123456
CERTX_SMTP_ADDR=smtp.example.com:587
CERTX_SMTP_USER=certx@example.com
CERTX_SMTP_PASSWORD=...
CERTX_EMAIL_FROM=certx@example.com
CERTX_EMAIL_TO=ops@example.com,oncall@example.com
CERTX_ALERT_DAYS=14
```

`renew` notifies only when something happened: a renewal, a failure, or a
certificate expiring within `--alert-days`. Tokens and passwords never appear
in output or logs.

### Files

| Path | Content |
|---|---|
| `/var/lib/certx/certs/<name>/` | `fullchain.pem`, `privkey.pem` (0600), `cert.pem`, `chain.pem`, `meta.json` |
| `/var/lib/certx/accounts/` | ACME account keys (0600) |
| `/var/lib/certx/backups/` | configuration backups and manifests for `rollback` |
| `/var/lib/certx/audit.log` | JSON audit trail |
| `/var/lib/certx/state.json` | last renewal run |
| `/var/log/certx/certx.log` | renewal log including ACME protocol details (rotated, 5 × 10 MiB) |

`issue`, `deploy` and `rollback` show a diff and ask for confirmation; use
`--yes` for automation and `--dry-run` to only preview.

Try discovery without a web server installed:

```sh
go run ./cmd/certx --nginx-conf tests/fixtures/nginx/nginx.conf \
                   --apache-conf tests/fixtures/apache-debian/apache2.conf
```

### How issuance works

1. DNS preflight (warning only — the ACME challenge proves control).
2. A temporary `/.well-known/acme-challenge/` location is added to every vhost
   serving the domains (Nginx `location ^~`, Apache `Alias` plus a
   `ProxyPass ... !` exclusion), then tested and reloaded.
3. A self-check fetches a token through the local web server, so permission or
   routing problems are reported **before** spending Let's Encrypt rate limits.
4. lego completes HTTP-01; the temporary configuration is always removed.
5. Files are stored in `/var/lib/certx/certs/<name>/` (`privkey.pem` is `0600`).

### How deploy changes configuration

| | Nginx | Apache |
|---|---|---|
| Site already on TLS | replaces `ssl_certificate` / `ssl_certificate_key` | replaces `SSLCertificateFile` / `SSLCertificateKeyFile`, comments out `SSLCertificateChainFile` |
| Plain HTTP site | adds `listen 443 ssl` and certificate directives to the same block | creates `<site>-certx-ssl.conf` (a copy of the vhost on `:443`) and enables it |
| `--redirect` | `if ($scheme != "https") { return 301 ... }` | `RewriteRule` (works with `ProxyPass /`), ACME path excluded |

Hosts whose certificates live in `/etc/letsencrypt` are treated as
Certbot-managed and skipped unless `--force` is given.

### TUI keys

| Key | Action |
|---|---|
| `↑/↓`, `j/k`, `pgup/pgdn`, `g/G` | Move |
| `enter` | Host and certificate details |
| `t` (in details) | Fetch the certificate served over TLS and compare |
| `d` (in details) | Preview the configuration diff `certx deploy` would apply |
| `n` / `N` (in details) | Next / previous host |
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
| `--storage` | `CERTX_STORAGE` | `/var/lib/certx` |
| `--email` | `CERTX_EMAIL` | |
| `--acme` | `CERTX_ACME` | `staging` (`production` or an https directory URL) |
| `--domain` | | repeatable or comma-separated |
| `--webroot` | | use an existing webroot instead of the temporary snippet |
| `--window-days` | `CERTX_RENEW_DAYS` | `30` |
| `--alert-days` | `CERTX_ALERT_DAYS` | `14` |
| `--log-file` | `CERTX_LOG_FILE` | `/var/log/certx/certx.log` |
| `--timeout` | | `30m` |
| `--scheduler` | | `auto` (`systemd` or `cron`) |
| `--deploy`, `--redirect`, `--force`, `--dry-run`, `--yes`, `--json`, `--quiet` | | `false` |
| | `CERTX_ENV_FILE` | `/etc/certx/env` |

### Statuses

`OK`, `NO TLS`, `SELF-SIGNED`, `EXPIRING`, `BAD CHAIN`, `MISMATCH`,
`NOT YET VALID`, `KEY MISMATCH`, `EXPIRED`, `ERROR` (ordered by severity).
`scan` exits with code `2` when an enabled host is `MISMATCH` or worse;
`renew` exits with `1` when any renewal failed.

## Development

```sh
go test ./...
go vet ./...
sudo tests/e2e/pebble.sh   # real nginx + apache2 + Pebble test CA (disposable machine only)
```
