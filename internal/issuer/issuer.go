// Package issuer orchestrates certificate issuance: temporary challenge
// configuration, local self-check, ACME order with retries and cleanup.
package issuer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bakhod1r/certx/internal/acme"
	"github.com/bakhod1r/certx/internal/certificate"
	"github.com/bakhod1r/certx/internal/deployment"
	"github.com/bakhod1r/certx/internal/discovery"
	"github.com/bakhod1r/certx/internal/plan"
	"github.com/bakhod1r/certx/internal/webserver"
)

// Retry controls how transient ACME and network failures are retried.
type Retry struct {
	Attempts int
	Delay    time.Duration // doubled after every attempt
}

// DefaultRetry is used for scheduled renewals.
var DefaultRetry = Retry{Attempts: 3, Delay: 30 * time.Second}

// Request describes one certificate to obtain.
type Request struct {
	Inv       *discovery.Inventory
	Storage   string
	Directory string
	Email     string
	Domains   []string
	Webroot   string // existing webroot; empty means a temporary challenge snippet
	Retry     Retry
	Out       io.Writer // progress output; nil discards
}

// Plan is what Execute will do.
type Plan struct {
	Name      string
	Paths     webserver.CertPaths
	Webroot   string
	Challenge *webserver.ChangeSet // nil or empty when an existing webroot is used
}

// Prepare validates the request and computes the challenge configuration.
func Prepare(req Request) (*Plan, error) {
	if len(req.Domains) == 0 {
		return nil, errors.New("no domains")
	}
	for _, d := range req.Domains {
		if _, err := acme.CertName(d); err != nil || strings.HasPrefix(d, "*.") {
			return nil, fmt.Errorf("invalid domain %q (wildcards need DNS-01, which is not supported yet)", d)
		}
	}
	name, _ := acme.CertName(req.Domains[0])
	p := &Plan{Name: name, Paths: acme.Paths(req.Storage, name), Webroot: req.Webroot}
	if p.Webroot != "" {
		return p, nil
	}
	p.Webroot = filepath.Join(req.Storage, "acme-challenge")
	hosts := plan.Serving(req.Inv, req.Domains)
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no enabled virtual host serves %s; add one or pass --webroot", strings.Join(req.Domains, ", "))
	}
	cs, err := plan.Changes(req.Inv, "acme challenge for "+name, hosts, plan.Challenge(p.Webroot))
	if err != nil {
		return nil, err
	}
	p.Challenge = cs
	return p, nil
}

// Execute obtains and stores the certificate. The temporary challenge
// configuration is always removed again, whatever the outcome.
func Execute(ctx context.Context, req Request, p *Plan) (*certificate.Info, error) {
	out := req.Out
	if out == nil {
		out = io.Discard
	}
	step := func(s string) { fmt.Fprintln(out, "…", s) }
	backups := filepath.Join(req.Storage, "backups")
	targets := Targets(req.Inv)

	if err := os.MkdirAll(filepath.Join(p.Webroot, ".well-known", "acme-challenge"), 0o755); err != nil {
		return nil, err
	}
	var applied *deployment.Manifest
	if !p.Challenge.Empty() {
		step("Adding temporary challenge configuration")
		var err error
		if applied, err = deployment.Apply(ctx, p.Challenge, targets, backups); err != nil {
			return nil, err
		}
	}

	step("Checking that the challenge is reachable locally")
	err := acme.SelfTest(ctx, p.Webroot, req.Domains, "127.0.0.1")
	var bundle *acme.Bundle
	if err == nil {
		bundle, err = obtain(ctx, req, p.Webroot, step)
	}

	if applied != nil {
		step("Removing temporary challenge configuration")
		if _, rerr := deployment.Rollback(context.WithoutCancel(ctx), backups, applied.ID, targets); rerr != nil {
			return nil, errors.Join(err, fmt.Errorf("removing challenge configuration (backup %s): %w", applied.ID, rerr))
		}
	}
	if err != nil {
		return nil, err
	}

	info, err := certificate.InspectPEM(bundle.FullChain, time.Now())
	if err != nil {
		return nil, err
	}
	_, err = acme.Save(req.Storage, p.Name, bundle, acme.Meta{
		Domains: req.Domains, Directory: req.Directory, Email: req.Email,
		Serial: info.Serial, IssuedAt: time.Now().UTC(), NotAfter: info.NotAfter,
	})
	return info, err
}

// obtain runs the ACME order, retrying transient failures with backoff.
func obtain(ctx context.Context, req Request, webroot string, step func(string)) (*acme.Bundle, error) {
	r := req.Retry
	if r.Attempts < 1 {
		r.Attempts = 1
	}
	delay := r.Delay
	for attempt := 1; ; attempt++ {
		step("Requesting certificate")
		b, err := obtainCtx(ctx, acme.Request{
			Storage: req.Storage, Directory: req.Directory, Email: req.Email, Domains: req.Domains, Webroot: webroot,
		})
		if err == nil || attempt >= r.Attempts || !Transient(err) {
			return b, err
		}
		step(fmt.Sprintf("Transient error (attempt %d/%d), retrying in %s: %v", attempt, r.Attempts, delay, firstLine(err)))
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
	}
}

// obtainFn is replaced in tests.
var obtainFn = acme.Obtain

// obtainCtx bounds acme.Obtain (which has no context support) by ctx.
func obtainCtx(ctx context.Context, r acme.Request) (*acme.Bundle, error) {
	type result struct {
		b   *acme.Bundle
		err error
	}
	ch := make(chan result, 1)
	go func() {
		b, err := obtainFn(r)
		ch <- result{b, err}
	}()
	select {
	case res := <-ch:
		return res.b, res.err
	case <-ctx.Done():
		return nil, fmt.Errorf("certificate request: %w", ctx.Err())
	}
}

// Transient reports whether err is worth retrying. Authorization failures
// and rate limits are permanent: retrying only burns rate limits.
func Transient(err error) bool {
	msg := strings.ToLower(err.Error())
	for _, p := range []string{"ratelimited", "too many", "unauthorized", "caa", "rejectedidentifier", "malformed"} {
		if strings.Contains(msg, p) {
			return false
		}
	}
	for _, p := range []string{"timeout", "connection refused", "connection reset", "eof", "no such host",
		"temporary failure", "503", "502", "500 ", "serverinternal", "badnonce", "tls handshake"} {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}

// Targets maps every detected server to its adapter for validate/reload.
func Targets(inv *discovery.Inventory) map[webserver.Kind]deployment.Target {
	t := map[webserver.Kind]deployment.Target{}
	for _, s := range inv.Servers {
		if a := inv.Adapter(s.Kind); a != nil && s.Found {
			t[s.Kind] = deployment.Target{Adapter: a, Inst: s}
		}
	}
	return t
}

func firstLine(err error) string {
	s, _, _ := strings.Cut(err.Error(), "\n")
	return s
}
