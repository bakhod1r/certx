// Package discovery runs every web server adapter, merges the inventory and
// audits the certificates of each virtual host.
package discovery

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/bakhod1r/certx/internal/certificate"
	"github.com/bakhod1r/certx/internal/webserver"
	"github.com/bakhod1r/certx/internal/webserver/apache"
	"github.com/bakhod1r/certx/internal/webserver/nginx"
)

// Status is the health of a virtual host, ordered by severity.
type Status string

const (
	StatusOK          Status = "OK"
	StatusNoTLS       Status = "NO TLS"
	StatusSelfSigned  Status = "SELF-SIGNED"
	StatusExpiring    Status = "EXPIRING"
	StatusBadChain    Status = "BAD CHAIN"
	StatusMismatch    Status = "MISMATCH"
	StatusNotYetValid Status = "NOT YET VALID"
	StatusKeyMismatch Status = "KEY MISMATCH"
	StatusExpired     Status = "EXPIRED"
	StatusError       Status = "ERROR"
)

var severity = map[Status]int{
	StatusOK: 0, StatusNoTLS: 1, StatusSelfSigned: 2, StatusExpiring: 3, StatusBadChain: 4,
	StatusMismatch: 5, StatusNotYetValid: 6, StatusKeyMismatch: 7, StatusExpired: 8, StatusError: 9,
}

// Severity returns a sortable rank; higher is worse.
func (s Status) Severity() int { return severity[s] }

// Critical reports whether the status should fail CI pipelines.
func (s Status) Critical() bool { return s.Severity() >= StatusMismatch.Severity() }

// Options configures a scan.
type Options struct {
	Servers      []webserver.Kind // empty means all
	NginxConfig  string
	ApacheConfig string
	ApacheRoot   string
	WarnDays     int
	Now          func() time.Time
}

// Host is a virtual host together with its audit result.
type Host struct {
	webserver.VirtualHost
	Cert   *certificate.Info `json:"certificate,omitempty"`
	Status Status            `json:"status"`
	Issues []string          `json:"issues,omitempty"`
}

// Inventory is the result of a scan.
type Inventory struct {
	ScannedAt time.Time                `json:"scanned_at"`
	Servers   []webserver.Installation `json:"servers"`
	Hosts     []Host                   `json:"hosts"`
	Warnings  []string                 `json:"warnings,omitempty"`

	adapters map[webserver.Kind]webserver.Adapter
}

// Adapter returns the adapter that produced hosts of kind k.
func (inv *Inventory) Adapter(k webserver.Kind) webserver.Adapter { return inv.adapters[k] }

// Installation returns the detected installation of kind k.
func (inv *Inventory) Installation(k webserver.Kind) webserver.Installation {
	for _, s := range inv.Servers {
		if s.Kind == k {
			return s
		}
	}
	return webserver.Installation{Kind: k}
}

// Adapters returns the adapters selected by opts.
func Adapters(opts Options) []webserver.Adapter {
	all := []webserver.Adapter{
		&nginx.Adapter{ConfigPath: opts.NginxConfig},
		&apache.Adapter{ConfigPath: opts.ApacheConfig, ServerRoot: opts.ApacheRoot},
	}
	if len(opts.Servers) == 0 {
		return all
	}
	var out []webserver.Adapter
	for _, a := range all {
		for _, k := range opts.Servers {
			if a.Kind() == k {
				out = append(out, a)
			}
		}
	}
	return out
}

// Scan detects web servers, discovers virtual hosts and audits certificates.
func Scan(ctx context.Context, opts Options) (*Inventory, error) {
	now := time.Now()
	if opts.Now != nil {
		now = opts.Now()
	}
	if opts.WarnDays <= 0 {
		opts.WarnDays = 30
	}
	inv := &Inventory{ScannedAt: now, adapters: map[webserver.Kind]webserver.Adapter{}}
	for _, a := range Adapters(opts) {
		inst := a.Detect(ctx)
		inv.adapters[a.Kind()] = a
		inv.Servers = append(inv.Servers, inst)
		if !inst.Found {
			continue
		}
		res, err := a.Discover(ctx, inst)
		if err != nil {
			inv.Warnings = append(inv.Warnings, fmt.Sprintf("%s: %v", a.Kind(), err))
			continue
		}
		inv.Warnings = append(inv.Warnings, res.Warnings...)
		for _, vh := range res.Hosts {
			h := Host{VirtualHost: vh}
			evaluate(&h, opts.WarnDays, now)
			inv.Hosts = append(inv.Hosts, h)
		}
	}
	markDuplicates(inv.Hosts)
	if len(inv.Hosts) == 0 && !anyFound(inv.Servers) {
		inv.Warnings = append(inv.Warnings, "no Nginx or Apache installation detected; use --nginx-conf or --apache-conf")
	}
	return inv, nil
}

// Validate runs the configuration test of every detected server.
func Validate(ctx context.Context, inv *Inventory) string {
	var b strings.Builder
	for _, inst := range inv.Servers {
		a := inv.Adapter(inst.Kind)
		if a == nil || !inst.Found {
			continue
		}
		out, err := a.Validate(ctx, inst)
		state := "OK"
		if err != nil {
			state = "FAILED: " + err.Error()
		}
		fmt.Fprintf(&b, "== %s (%s) — %s\n%s\n\n", inst.Kind, orDash(inst.Binary), state, out)
	}
	if b.Len() == 0 {
		return "No web server installation detected."
	}
	return strings.TrimSpace(b.String())
}

// PublicNames returns the normalised names of h that can be certified.
func PublicNames(h Host) []string {
	var out []string
	for _, n := range h.Names {
		if c := checkable(n); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// ProbeName returns the first public-looking name of a host, if any.
func ProbeName(h Host) string {
	for _, n := range h.Names {
		if n = checkable(n); n != "" && !strings.HasPrefix(n, "*") {
			return n
		}
	}
	return ""
}

func evaluate(h *Host, warnDays int, now time.Time) {
	if h.CertFile == "" {
		if h.TLS() {
			h.Status = StatusError
			h.Issues = append(h.Issues, "TLS listener without a certificate")
			return
		}
		h.Status = StatusNoTLS
		if !h.RedirectsToHTTPS {
			h.Issues = append(h.Issues, "serves plain HTTP only")
		}
		return
	}
	info, err := certificate.Inspect(h.CertFile, h.KeyFile, now)
	if err != nil {
		h.Status = StatusError
		h.Issues = append(h.Issues, err.Error())
		return
	}
	h.Cert = info
	status := StatusOK
	raise := func(s Status, msg string) {
		if s.Severity() > status.Severity() {
			status = s
		}
		h.Issues = append(h.Issues, msg)
	}

	switch {
	case info.KeyError != "":
		raise(StatusError, "private key: "+info.KeyError)
	case info.KeyMatch != nil && !*info.KeyMatch:
		raise(StatusKeyMismatch, "certificate and private key do not match")
	}
	if info.KeyPermissive {
		h.Issues = append(h.Issues, "private key is readable by group or others")
	}
	switch {
	case now.After(info.NotAfter):
		raise(StatusExpired, fmt.Sprintf("expired %d days ago", -info.DaysLeft))
	case now.Before(info.NotBefore):
		raise(StatusNotYetValid, "not valid before "+info.NotBefore.Format(time.DateOnly))
	case info.DaysLeft <= warnDays:
		raise(StatusExpiring, fmt.Sprintf("expires in %d days", info.DaysLeft))
	}
	for _, n := range h.Names {
		if c := checkable(n); c != "" && !info.Covers(c) {
			raise(StatusMismatch, "certificate does not cover "+c)
		}
	}
	if info.SelfSigned {
		raise(StatusSelfSigned, "self-signed certificate")
	} else if info.ChainError != "" {
		raise(StatusBadChain, "chain: "+info.ChainError)
	}
	if !h.TLS() {
		h.Issues = append(h.Issues, "certificate configured but no TLS listener")
	}
	h.Status = status
}

// checkable normalises a server name and returns "" for names that cannot
// be publicly certified (regex names, catch-all, localhost, IPs).
func checkable(n string) string {
	n = strings.TrimPrefix(strings.ToLower(n), ".")
	switch {
	case n == "", n == "_", n == "localhost", strings.HasPrefix(n, "~"), strings.ContainsAny(n, "$\""):
		return ""
	case net.ParseIP(n) != nil, !strings.Contains(n, "."):
		return ""
	case strings.HasSuffix(n, ".local"), strings.HasSuffix(n, ".internal"), strings.HasSuffix(n, ".localhost"):
		return ""
	}
	return n
}

func markDuplicates(hosts []Host) {
	type key struct {
		server webserver.Kind
		name   string
		tls    bool
	}
	seen := map[key]int{}
	for i := range hosts {
		h := &hosts[i]
		if !h.Enabled {
			continue
		}
		for _, n := range h.Names {
			if n == "_" || n == "" {
				continue
			}
			k := key{h.Server, strings.ToLower(n), h.TLS()}
			if j, ok := seen[k]; ok {
				msg := fmt.Sprintf("duplicate server name %s (also %s)", n, hosts[j].Location())
				h.Issues = append(h.Issues, msg)
				continue
			}
			seen[k] = i
		}
	}
}

func anyFound(insts []webserver.Installation) bool {
	for _, i := range insts {
		if i.Found {
			return true
		}
	}
	return false
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
