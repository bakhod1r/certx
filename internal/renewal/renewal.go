// Package renewal renews CertX-managed certificates that are inside the
// renewal window and reloads the web servers that use them.
package renewal

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/bakhod1r/certx/internal/acme"
	"github.com/bakhod1r/certx/internal/certificate"
	"github.com/bakhod1r/certx/internal/discovery"
	"github.com/bakhod1r/certx/internal/issuer"
	"github.com/bakhod1r/certx/internal/webserver"
)

// Action is what happened to a certificate.
type Action string

const (
	Renewed     Action = "renewed"
	Skipped     Action = "skipped"
	WouldRenew  Action = "would-renew"
	Failed      Action = "failed"
	NotDeployed Action = "renewed-not-deployed"
)

// Options configure a renewal run.
type Options struct {
	Inv              *discovery.Inventory
	Storage          string
	DefaultDirectory string
	DefaultEmail     string
	WindowDays       int
	Force            bool
	DryRun           bool
	Domains          []string // restrict to certificates covering any of these
	Retry            issuer.Retry
	Out              io.Writer
	Now              func() time.Time
}

// Result is the outcome for one certificate.
type Result struct {
	Name     string    `json:"name"`
	Domains  []string  `json:"domains"`
	Action   Action    `json:"action"`
	Reason   string    `json:"reason"`
	NotAfter time.Time `json:"not_after,omitzero"`
	DaysLeft int       `json:"days_left"`
	Servers  []string  `json:"servers,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// Hooks are replaced in tests.
var (
	executeFn  = issuer.Execute
	targetsFn  = issuer.Targets
	verifyWait = 8 * time.Second
	verifyFn   = func(ctx context.Context, domain string, now time.Time) (*certificate.Info, error) {
		return certificate.Remote(ctx, domain, 443, domain, now)
	}
)

// Run renews every eligible certificate. It never stops at the first
// failure: each certificate is handled independently.
func Run(ctx context.Context, o Options) ([]Result, error) {
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	out := o.Out
	if out == nil {
		out = io.Discard
	}
	names, err := acme.List(o.Storage)
	if err != nil {
		return nil, err
	}
	var results []Result
	for _, name := range names {
		meta, err := acme.LoadMeta(o.Storage, name)
		if err != nil {
			results = append(results, Result{Name: name, Action: Failed, Error: "metadata: " + err.Error()})
			continue
		}
		if len(o.Domains) > 0 && !overlaps(meta.Domains, o.Domains) {
			continue
		}
		results = append(results, renewOne(ctx, o, name, meta, now(), out))
	}
	return results, nil
}

func renewOne(ctx context.Context, o Options, name string, meta *acme.Meta, now time.Time, out io.Writer) Result {
	r := Result{Name: name, Domains: meta.Domains}
	paths := acme.Paths(o.Storage, name)
	info, err := certificate.Inspect(paths.Cert, paths.Key, now)
	switch {
	case err != nil:
		r.Reason = "certificate unreadable: " + err.Error()
	case info.KeyMatch == nil || !*info.KeyMatch:
		r.Reason = "certificate and key do not match"
	case !coversAll(info, meta.Domains):
		r.Reason = "certificate does not cover all configured domains"
	default:
		r.NotAfter, r.DaysLeft = info.NotAfter, info.DaysLeft
		if info.DaysLeft > o.WindowDays && !o.Force {
			r.Action, r.Reason = Skipped, fmt.Sprintf("valid for %d more days", info.DaysLeft)
			return r
		}
		r.Reason = fmt.Sprintf("expires in %d days", info.DaysLeft)
		if o.Force {
			r.Reason = "forced"
		}
	}
	if o.DryRun {
		r.Action = WouldRenew
		return r
	}

	fmt.Fprintf(out, "Renewing %s (%s)\n", strings.Join(meta.Domains, ", "), r.Reason)
	req := issuer.Request{
		Inv: o.Inv, Storage: o.Storage, Directory: or(meta.Directory, o.DefaultDirectory),
		Email: or(meta.Email, o.DefaultEmail), Domains: meta.Domains, Retry: o.Retry, Out: out,
	}
	p, err := issuer.Prepare(req)
	if err == nil {
		info, err = executeFn(ctx, req, p)
	}
	if err != nil {
		r.Action, r.Error = Failed, err.Error()
		return r
	}
	r.NotAfter, r.DaysLeft = info.NotAfter, info.DaysLeft

	// Files were replaced in place; servers using them need a reload.
	kinds := serversUsing(o.Inv, paths.Cert)
	if len(kinds) == 0 {
		r.Action = NotDeployed
		r.Reason = "no enabled virtual host uses this certificate (run certx deploy)"
		return r
	}
	targets := targetsFn(o.Inv)
	for _, k := range kinds {
		t, ok := targets[k]
		if !ok || t.Inst.Binary == "" {
			r.Action, r.Error = Failed, fmt.Sprintf("%s binary not found; reload it manually", k)
			return r
		}
		if msg, err := t.Adapter.Validate(ctx, t.Inst); err != nil {
			r.Action, r.Error = Failed, fmt.Sprintf("%s configuration test failed, not reloaded:\n%s", k, msg)
			return r
		}
		if msg, err := t.Adapter.Reload(ctx, t.Inst); err != nil {
			r.Action, r.Error = Failed, fmt.Sprintf("%s reload failed: %v\n%s", k, err, msg)
			return r
		}
		r.Servers = append(r.Servers, string(k))
	}
	r.Action = Renewed
	for _, d := range meta.Domains {
		if msg := verify(ctx, d, info.FingerprintSHA256); msg != "" {
			r.Reason = msg
		}
	}
	return r
}

// verify waits briefly for the reload and reports a mismatch, if any.
func verify(ctx context.Context, domain, fingerprint string) string {
	var last string
	for deadline := time.Now().Add(verifyWait); ; {
		remote, err := verifyFn(ctx, domain, time.Now())
		switch {
		case err != nil:
			last = fmt.Sprintf("could not verify https://%s: %v", domain, err)
		case remote.FingerprintSHA256 != fingerprint:
			last = fmt.Sprintf("https://%s still serves serial %s", domain, remote.Serial)
		default:
			return ""
		}
		if time.Now().After(deadline) {
			return last
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func serversUsing(inv *discovery.Inventory, cert string) []webserver.Kind {
	var kinds []webserver.Kind
	for _, h := range inv.Hosts {
		if h.Enabled && h.CertFile != "" && webserver.RealPath(h.CertFile) == webserver.RealPath(cert) && !slices.Contains(kinds, h.Server) {
			kinds = append(kinds, h.Server)
		}
	}
	return kinds
}

func coversAll(info *certificate.Info, domains []string) bool {
	for _, d := range domains {
		if !info.Covers(d) {
			return false
		}
	}
	return true
}

func overlaps(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if strings.EqualFold(x, y) {
				return true
			}
		}
	}
	return false
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
