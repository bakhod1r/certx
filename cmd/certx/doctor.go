package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/bakhod1r/certx/internal/acme"
	"github.com/bakhod1r/certx/internal/certificate"
	"github.com/bakhod1r/certx/internal/discovery"
	"github.com/bakhod1r/certx/internal/metrics"
	"github.com/bakhod1r/certx/internal/plan"
	"github.com/bakhod1r/certx/internal/preflight"
	"github.com/bakhod1r/certx/internal/scheduler"
	"github.com/bakhod1r/certx/internal/state"
)

var errDoctor = errors.New("doctor found problems")

type report struct {
	section string
	fails   int
	warns   int
}

func (r *report) head(s string) { fmt.Printf("\n%s\n", s) }

func (r *report) line(sev preflight.Severity, format string, args ...any) {
	mark := map[preflight.Severity]string{preflight.OK: "✔", preflight.Warn: "⚠", preflight.Fail: "✖"}[sev]
	fmt.Printf("  %s %s\n", mark, fmt.Sprintf(format, args...))
	switch sev {
	case preflight.Fail:
		r.fails++
	case preflight.Warn:
		r.warns++
	}
}

func cmdDoctor(g *globals) error {
	r := &report{}
	ctx := context.Background()

	r.head("System")
	if os.Geteuid() == 0 {
		r.line(preflight.OK, "running as root")
	} else {
		r.line(preflight.Warn, "not running as root: configuration writes, reloads and %s need root", g.storage)
	}
	if out, err := exec.Command("certbot", "--version").CombinedOutput(); err == nil {
		r.line(preflight.OK, "%s installed; CertX leaves Certbot-managed certificates alone", strings.TrimSpace(string(out)))
	}

	r.head("Web servers")
	inv, err := scan(g)
	if err != nil {
		return err
	}
	found := false
	for _, s := range inv.Servers {
		if !s.Found {
			continue
		}
		found = true
		label := fmt.Sprintf("%s %s (%s, %s)", s.Kind, orDash(s.Version), orDash(s.Binary), orDash(s.ConfigPath))
		if s.Binary == "" {
			r.line(preflight.Fail, "%s: binary not found, cannot test or reload", label)
			continue
		}
		if out, err := inv.Adapter(s.Kind).Validate(ctx, s); err != nil {
			r.line(preflight.Fail, "%s: configuration test failed\n%s", label, indent(out, "      "))
		} else {
			r.line(preflight.OK, "%s: configuration test passed", label)
		}
	}
	if !found {
		r.line(preflight.Fail, "no Nginx or Apache installation detected (use --nginx-conf / --apache-conf)")
	}
	for _, w := range inv.Warnings {
		r.line(preflight.Warn, "%s", w)
	}
	for _, port := range []int{80, 443} {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
		if err != nil {
			sev := preflight.Warn
			if port == 80 {
				sev = preflight.Fail // HTTP-01 needs it
			}
			r.line(sev, "nothing listens on port %d locally", port)
			continue
		}
		conn.Close()
		r.line(preflight.OK, "port %d is listening", port)
	}

	r.head("Storage")
	doctorStorage(r, g.storage)
	if fi, err := os.Stat(envOr("CERTX_ENV_FILE", "/etc/certx/env")); err == nil {
		if fi.Mode().Perm()&0o077 != 0 {
			r.line(preflight.Fail, "%s is readable by group or others (chmod 600)", fi.Name())
		} else {
			r.line(preflight.OK, "%s permissions are 0600", envOr("CERTX_ENV_FILE", "/etc/certx/env"))
		}
	}

	names, _ := acme.List(g.storage)
	for _, n := range names {
		if meta, err := acme.LoadMeta(g.storage, n); err == nil && meta.DNS != "" {
			if err := acme.CheckDNSProvider(meta.DNS); err != nil {
				r.line(preflight.Fail, "%s renews over DNS-01 but %v; put the credentials in /etc/certx/env", n, err)
			} else {
				r.line(preflight.OK, "%s: DNS-01 provider %s credentials present", n, meta.DNS)
			}
		}
	}

	r.head("Certificate authority")
	dir, err := acme.DirectoryURL(g.acme)
	if err != nil {
		return err
	}
	doctorCA(r, dir)

	r.head("Domains")
	actions := plan.Actions(inv, plan.Options{Domains: g.domains, Force: true, Filter: g.filter})
	if len(actions) == 0 {
		r.line(preflight.Warn, "no enabled virtual hosts with public names")
	}
	opts := preflight.Options{CAIdentities: preflight.CAIdentities(dir)}
	seen := map[string]bool{}
	for _, a := range actions {
		for _, n := range a.Names {
			if seen[n] {
				continue
			}
			seen[n] = true
			dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			for _, c := range preflight.Domain(dctx, n, opts) {
				if c.Severity == preflight.OK && c.Name != "CAA" && !strings.HasPrefix(c.Name, "port") {
					continue
				}
				r.line(c.Severity, "%s %s: %s", n, c.Name, c.Detail)
			}
			cancel()
		}
	}
	for _, h := range inv.Hosts {
		if h.Enabled && h.Status.Critical() {
			r.line(preflight.Fail, "%s (%s): %s", strings.Join(h.Names, ", "), h.Location(), h.Status)
		} else if h.Enabled && h.Status == discovery.StatusWeak {
			r.line(preflight.Warn, "%s (%s): %s", strings.Join(h.Names, ", "), h.Location(), strings.Join(h.Issues, "; "))
		}
	}

	r.head("Automation")
	st := scheduler.Default().Status(ctx)
	if st.Kind == "" {
		r.line(preflight.Warn, "no renewal job installed (certx scheduler install)")
	} else {
		r.line(preflight.OK, "%s renewal job installed; next run %s", st.Kind, orDash(st.NextRun))
	}
	for _, c := range st.Conflicts {
		r.line(preflight.Warn, "%s", c)
	}
	switch last, err := state.LastRun(g.storage); {
	case err != nil:
		r.line(preflight.Warn, "last run unreadable: %v", err)
	case last == nil:
		r.line(preflight.Warn, "certx renew has never run")
	case !last.OK():
		r.line(preflight.Fail, "last renew at %s had %d failure(s)", last.Finished.Local().Format(time.DateTime), last.Failed)
	case time.Since(last.Finished) > 36*time.Hour:
		r.line(preflight.Warn, "last renew ran %s ago; is the scheduler running?", time.Since(last.Finished).Round(time.Hour))
	default:
		r.line(preflight.OK, "last renew succeeded %s ago", time.Since(last.Finished).Round(time.Minute))
	}

	fmt.Printf("\n%d problem(s), %d warning(s)\n", r.fails, r.warns)
	if r.fails > 0 {
		return errDoctor
	}
	return nil
}

func doctorStorage(r *report, storage string) {
	fi, err := os.Stat(storage)
	if errors.Is(err, fs.ErrNotExist) {
		r.line(preflight.OK, "%s does not exist yet (created on first issue)", storage)
		return
	}
	if err != nil {
		r.line(preflight.Fail, "%s: %v", storage, err)
		return
	}
	if !fi.IsDir() {
		r.line(preflight.Fail, "%s is not a directory", storage)
		return
	}
	// The web server user must traverse every parent to serve challenges.
	for dir := filepath.Join(storage, "acme-challenge"); ; dir = filepath.Dir(dir) {
		if fi, err := os.Stat(dir); err == nil && fi.Mode().Perm()&0o001 == 0 {
			r.line(preflight.Fail, "%s is not world-traversable (mode %v): the web server cannot read HTTP-01 challenges", dir, fi.Mode().Perm())
			break
		}
		if dir == "/" || dir == "." {
			r.line(preflight.OK, "challenge directory is reachable by the web server user")
			break
		}
	}
	keys, _ := filepath.Glob(filepath.Join(storage, "certs", "*", "privkey.pem"))
	acct, _ := filepath.Glob(filepath.Join(storage, "accounts", "*", "*", "key.pem"))
	bad := 0
	for _, k := range append(keys, acct...) {
		if fi, err := os.Stat(k); err == nil && fi.Mode().Perm()&0o077 != 0 {
			r.line(preflight.Fail, "%s is readable by group or others (mode %v)", k, fi.Mode().Perm())
			bad++
		}
	}
	if bad == 0 {
		r.line(preflight.OK, "%d private key(s), all mode 0600", len(keys)+len(acct))
	}
}

// doctorCA fetches the ACME directory and compares clocks: ACME requests
// fail when the local clock is far off.
func doctorCA(r *report, dir string) {
	pool, _ := x509.SystemCertPool()
	if pool == nil {
		pool = x509.NewCertPool()
	}
	for _, f := range strings.Split(os.Getenv("LEGO_CA_CERTIFICATES"), string(os.PathListSeparator)) {
		if pem, err := os.ReadFile(f); err == nil {
			pool.AppendCertsFromPEM(pem)
		}
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{RootCAs: pool},
	}}
	resp, err := client.Get(dir)
	if err != nil {
		r.line(preflight.Fail, "cannot reach %s: %v", dir, err)
		return
	}
	defer resp.Body.Close()
	var body bytes.Buffer
	_, _ = body.ReadFrom(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body.String(), "newAccount") {
		r.line(preflight.Fail, "%s returned HTTP %d, not an ACME directory", dir, resp.StatusCode)
		return
	}
	r.line(preflight.OK, "%s reachable", dir)
	if t, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
		if skew := time.Since(t); skew > 5*time.Minute || skew < -5*time.Minute {
			r.line(preflight.Fail, "local clock differs from the CA by %s; fix NTP", skew.Round(time.Second))
		} else {
			r.line(preflight.OK, "clock skew %s", skew.Round(time.Second))
		}
	}
}

// ---------------------------------------------------------------- revoke

func cmdRevoke(g *globals) error {
	if len(g.domains) == 0 {
		return errors.New("--domain is required")
	}
	reason, ok := acme.RevocationReasons[g.reason]
	if !ok {
		return fmt.Errorf("unknown --reason %q", g.reason)
	}
	name, meta, err := acme.Find(g.storage, g.domains[0])
	if err != nil {
		return err
	}
	p := acme.Paths(g.storage, name)
	certPEM, err := os.ReadFile(filepath.Join(filepath.Dir(p.Cert), "cert.pem"))
	if err != nil {
		return err
	}
	info, err := certificate.InspectPEM(certPEM, time.Now())
	if err != nil {
		return err
	}
	if meta.RevokedSerial == info.Serial {
		return fmt.Errorf("certificate %s (serial %s) is already revoked", name, info.Serial)
	}
	dir := meta.Directory
	if dir == "" {
		if dir, err = acme.DirectoryURL(g.acme); err != nil {
			return err
		}
	}
	fmt.Printf("Revoke %s\n  domains: %s\n  serial:  %s\n  expires: %s\n  CA:      %s\n  reason:  %s\n",
		name, strings.Join(meta.Domains, ", "), info.Serial, info.NotAfter.Format(time.DateOnly), dir, g.reason)
	fmt.Println("Browsers will reject this certificate once revoked; the next `certx renew` issues a new one.")
	if g.dryRun {
		fmt.Println("Dry run: nothing was changed.")
		return nil
	}
	if !confirm(g.yes, "Revoke this certificate? This cannot be undone.") {
		return errors.New("aborted")
	}
	release, err := g.lock()
	if err != nil {
		return err
	}
	defer release()
	err = acme.Revoke(g.storage, dir, or(meta.Email, g.email), certPEM, reason)
	audit(g, "revoke", meta.Domains, err, "")
	if err != nil {
		return err
	}
	meta.RevokedSerial, meta.RevokedAt = info.Serial, time.Now().UTC()
	if err := acme.SaveMeta(g.storage, name, meta); err != nil {
		return err
	}
	fmt.Printf("✔ Revoked serial %s. Run `certx renew --domain %s` to replace it now.\n", info.Serial, g.domains[0])
	return nil
}

// ---------------------------------------------------------------- metrics

func cmdMetrics(g *globals) error {
	inv, err := scan(g)
	if err != nil {
		return err
	}
	last, _ := state.LastRun(g.storage)
	if g.metrics == "" {
		return metrics.Write(os.Stdout, inv, g.storage, last, time.Now())
	}
	return writeMetrics(g, inv, last)
}

func writeMetrics(g *globals, inv *discovery.Inventory, last *state.Run) error {
	var b bytes.Buffer
	if err := metrics.Write(&b, inv, g.storage, last, time.Now()); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(g.metrics), 0o755); err != nil {
		return err
	}
	return atomicWrite(g.metrics, b.Bytes())
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
