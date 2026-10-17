#!/usr/bin/env bash
# End-to-end test against real Nginx and Apache with the Pebble test CA.
# Run as root on a disposable Debian/Ubuntu machine or container:
#
#   sudo tests/e2e/pebble.sh
#
# It installs nginx, apache2 and Pebble, then for each server runs
# scan → plan → issue --deploy --redirect → HTTPS check → rollback.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
BIN="$WORK/bin"
PEBBLE_VERSION=v2.7.0
export GOBIN="$BIN" LEGO_CA_CERTIFICATES="$WORK/pebble.minica.pem"
ACME=https://localhost:14000/dir

PIDS=()
cleanup() {
  nginx -s stop 2>/dev/null || true
  apache2ctl stop 2>/dev/null || true
  # Kill by PID: a pattern such as "pebble" would also match this script.
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

step() { printf '\n\033[1;35m==> %s\033[0m\n' "$*"; }

step "Installing nginx, apache2, Pebble and CertX"
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx apache2 curl openssl >/dev/null
go install github.com/letsencrypt/pebble/v2/cmd/pebble@$PEBBLE_VERSION
go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@$PEBBLE_VERSION
(cd "$ROOT" && go build -o "$BIN/certx" ./cmd/certx)
nginx -s stop 2>/dev/null || true
apache2ctl stop 2>/dev/null || true

step "Starting Pebble (HTTP-01 on port 80) and a backend on :9000"
SRC=$(go env GOMODCACHE)/github.com/letsencrypt/pebble/v2@$PEBBLE_VERSION
cp "$SRC/test/certs/pebble.minica.pem" "$WORK/"
python3 - "$SRC" "$WORK/pebble.json" <<'PY'
import json, sys
src, out = sys.argv[1], sys.argv[2]
c = json.load(open(src + "/test/config/pebble-config.json"))
c["pebble"].update(httpPort=80, tlsPort=443,
                   certificate=src + "/test/certs/localhost/cert.pem",
                   privateKey=src + "/test/certs/localhost/key.pem")
json.dump(c, open(out, "w"))
PY
PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 "$BIN/pebble" -config "$WORK/pebble.json" -dnsserver 127.0.0.1:8053 >"$WORK/pebble.log" 2>&1 &
PIDS+=($!)
"$BIN/pebble-challtestsrv" -defaultIPv4 127.0.0.1 -defaultIPv6 "" -dns01 :8053 -http01 "" -https01 "" -tlsalpn01 "" -doh "" -management :8055 >"$WORK/chall.log" 2>&1 &
PIDS+=($!)
mkdir -p "$WORK/www" && echo "hello from backend" >"$WORK/www/index.html"
python3 -m http.server 9000 -d "$WORK/www" >/dev/null 2>&1 &
PIDS+=($!)
grep -q wild.certx.test /etc/hosts || echo "127.0.0.1 app.certx.test www.app.certx.test blog.certx.test wild.certx.test a.wild.certx.test" >>/etc/hosts
# DNS-01 through lego's exec provider and the challtestsrv management API.
cat >"$WORK/dns-hook.sh" <<'SH'
#!/bin/sh
case "$1" in
  present) curl -sf --noproxy '*' -d "{\"host\":\"$2\",\"value\":\"$3\"}" http://127.0.0.1:8055/set-txt ;;
  cleanup) curl -sf --noproxy '*' -d "{\"host\":\"$2\"}" http://127.0.0.1:8055/clear-txt ;;
esac
SH
chmod 755 "$WORK/dns-hook.sh"
export EXEC_PATH="$WORK/dns-hook.sh" CERTX_DNS_PROPAGATION_WAIT=2s # challtestsrv does not answer SOA
sleep 2

check_https() { # domain
  curl -fsS --noproxy '*' -o /dev/null -w "http  -> %{http_code} %{redirect_url}\n" "http://$1/x"
  curl -fsS --noproxy '*' -k "https://$1/" | grep -q "hello from backend"
  echo | openssl s_client -connect 127.0.0.1:443 -servername "$1" 2>/dev/null | openssl x509 -noout -issuer
}

step "Nginx"
cat >/etc/nginx/sites-available/app.conf <<'CONF'
server {
    listen 80;
    server_name app.certx.test www.app.certx.test;
    location / { proxy_pass http://127.0.0.1:9000; }
}
CONF
ln -sf /etc/nginx/sites-available/app.conf /etc/nginx/sites-enabled/app.conf
nginx -t && nginx
certx() { "$BIN/certx" "$@"; }
certx scan --server nginx || true
certx plan --server nginx
certx issue --server nginx --domain app.certx.test --domain www.app.certx.test \
  --acme "$ACME" --deploy --redirect --yes
check_https app.certx.test
serial() { echo | openssl s_client -connect 127.0.0.1:443 -servername "$1" 2>/dev/null | openssl x509 -noout -serial; }
BEFORE=$(serial app.certx.test)
certx renew --server nginx --domain app.certx.test --acme "$ACME" --dry-run
certx renew --server nginx --domain app.certx.test --acme "$ACME" --force
AFTER=$(serial app.certx.test)
[ "$BEFORE" != "$AFTER" ] || { echo "renew did not change the served certificate"; exit 1; }
certx renew --server nginx --domain app.certx.test --acme "$ACME" --window-days 1 | grep -q "valid for" # idempotent: skipped now (Pebble may issue short-lived certificates)
certx scheduler install --scheduler cron --yes
certx scheduler status
certx scheduler uninstall --yes
if command -v systemd-analyze >/dev/null; then
  UNITS="$WORK/units" && mkdir -p "$UNITS"
  certx scheduler install --scheduler systemd --dry-run | awk -v d="$UNITS" '/^--- /{f=d"/"substr($2, match($2, /[^\/]+$/)); next} /^Dry run/{f=""} f{print > f}'
  systemd-analyze verify --man=no "$UNITS/certx-renew.service" "$UNITS/certx-renew.timer"
fi

step "Nginx: wildcard over DNS-01, revoke, metrics, doctor"
cat >/etc/nginx/sites-available/wild.conf <<'CONF'
server {
    listen 80;
    server_name wild.certx.test *.wild.certx.test;
    location / { proxy_pass http://127.0.0.1:9000; }
}
CONF
ln -sf /etc/nginx/sites-available/wild.conf /etc/nginx/sites-enabled/wild.conf
nginx -s reload && sleep 1
if certx issue --server nginx --domain '*.wild.certx.test' --acme "$ACME" --yes 2>/dev/null; then
  echo "wildcard without --dns must be refused"; exit 1
fi
certx issue --server nginx --domain '*.wild.certx.test' --domain wild.certx.test --dns exec --acme "$ACME" --deploy --redirect --yes
check_https a.wild.certx.test
certx issue --server nginx --domain '*.wild.certx.test' --domain wild.certx.test --dns exec --acme "$ACME" --yes | grep -q "already exists"
certx revoke --domain wild.certx.test --reason superseded --yes
certx renew --server nginx --domain wild.certx.test --dry-run | grep -q "certificate was revoked"
certx renew --server nginx --domain wild.certx.test
certx metrics --server nginx | grep -q 'certx_managed_certificate_expiry_timestamp_seconds{name="_wildcard.wild.certx.test"}'
certx doctor --server nginx --acme "$ACME" || true
ID=$(certx rollback --list | awk '/deploy _wildcard/ && /applied/ {print $1; exit}')
certx rollback --server nginx --yes "$ID"
rm -f /etc/nginx/sites-enabled/wild.conf
ID=$(certx rollback --list | awk '/deploy app/ && /applied/ {print $1; exit}')
certx rollback --server nginx --yes "$ID"
nginx -s stop

step "Apache"
cat >/etc/apache2/sites-available/blog.conf <<'CONF'
<VirtualHost *:80>
    ServerName blog.certx.test
    ProxyPass / http://127.0.0.1:9000/
    ProxyPassReverse / http://127.0.0.1:9000/
</VirtualHost>
CONF
a2enmod -q ssl rewrite proxy proxy_http >/dev/null
a2ensite -q blog >/dev/null
apache2ctl -t && apache2ctl start
certx plan --server apache
certx issue --server apache --domain blog.certx.test --acme "$ACME" --deploy --redirect --yes
check_https blog.certx.test
ID=$(certx rollback --list | awk '/deploy blog/ && /applied/ {print $1; exit}')
certx rollback --server apache --yes "$ID"

step "All end-to-end checks passed"
