// Package plan decides which virtual hosts need certificates and computes
// the configuration changes needed to deploy them.
package plan

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/bakhod1r/certx/internal/discovery"
	"github.com/bakhod1r/certx/internal/webserver"
)

// Action is the recommendation for one TLS-capable site.
type Action struct {
	Host     discovery.Host
	Names    []string // publicly certifiable names
	NeedCert bool
	Reason   string
	Skip     string // non-empty when CertX will not touch the host
}

// Options tune planning.
type Options struct {
	Domains []string // restrict to hosts serving any of these names
	Force   bool     // also manage hosts whose certificates belong to another client
}

// Actions lists enabled sites with public names and what CertX would do.
// Plain HTTP hosts that only redirect, or that have a TLS sibling serving
// the same names, are folded into that sibling.
func Actions(inv *discovery.Inventory, o Options) []Action {
	var out []Action
	for _, h := range Targets(inv, o.Domains) {
		a := Action{Host: h, Names: discovery.PublicNames(h)}
		switch h.Status {
		case discovery.StatusOK:
			a.Reason = fmt.Sprintf("certificate valid for %d more days", h.Cert.DaysLeft)
		case discovery.StatusNoTLS:
			a.NeedCert, a.Reason = true, "site has no TLS"
		default:
			a.NeedCert, a.Reason = true, strings.ToLower(string(h.Status))
			if len(h.Issues) > 0 {
				a.Reason += ": " + h.Issues[0]
			}
		}
		if a.NeedCert && h.ManagedBy == "certbot" && !o.Force {
			a.Skip = "certificate is managed by Certbot (use --force to take over)"
		}
		out = append(out, a)
	}
	return out
}

// Targets returns enabled hosts that should carry a certificate for the
// given domains (all public hosts when domains is empty).
func Targets(inv *discovery.Inventory, domains []string) []discovery.Host {
	tlsNames := map[string]bool{}
	for _, h := range inv.Hosts {
		if h.Enabled && h.TLS() {
			for _, n := range discovery.PublicNames(h) {
				tlsNames[string(h.Server)+"|"+n] = true
			}
		}
	}
	var out []discovery.Host
	for _, h := range inv.Hosts {
		names := discovery.PublicNames(h)
		if !h.Enabled || len(names) == 0 || !matches(names, domains) {
			continue
		}
		if !h.TLS() {
			if h.RedirectsToHTTPS {
				continue
			}
			sibling := false
			for _, n := range names {
				sibling = sibling || tlsNames[string(h.Server)+"|"+n]
			}
			if sibling {
				continue
			}
		}
		out = append(out, h)
	}
	return out
}

// Serving returns every enabled host (HTTP and HTTPS) that answers for any
// of the domains; these are the hosts that must serve ACME challenges.
func Serving(inv *discovery.Inventory, domains []string) []discovery.Host {
	var out []discovery.Host
	for _, h := range inv.Hosts {
		if h.Enabled && matches(discovery.PublicNames(h), domains) {
			out = append(out, h)
		}
	}
	return out
}

func matches(names, domains []string) bool {
	if len(domains) == 0 {
		return true
	}
	for _, d := range domains {
		if slices.Contains(names, strings.ToLower(d)) {
			return true
		}
	}
	return false
}

// EditFunc edits the content of one virtual host's file.
type EditFunc func(a webserver.Adapter, src []byte, vh webserver.VirtualHost) (*webserver.Patch, error)

// Changes applies edit to every host and merges the results per file.
// Hosts in the same file are edited bottom-up so line numbers stay valid.
func Changes(inv *discovery.Inventory, label string, hosts []discovery.Host, edit EditFunc) (*webserver.ChangeSet, error) {
	byFile := map[string][]discovery.Host{}
	for _, h := range hosts {
		f := webserver.RealPath(h.File)
		byFile[f] = append(byFile[f], h)
	}
	files := make([]string, 0, len(byFile))
	for f := range byFile {
		files = append(files, f)
	}
	sort.Strings(files)

	cs := &webserver.ChangeSet{Label: label}
	servers := map[webserver.Kind]bool{}
	for _, f := range files {
		hs := byFile[f]
		sort.Slice(hs, func(i, j int) bool { return hs[i].Line > hs[j].Line })
		before, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		fi, err := os.Stat(f)
		if err != nil {
			return nil, err
		}
		cur := before
		for _, h := range hs {
			a := inv.Adapter(h.Server)
			if a == nil {
				return nil, fmt.Errorf("no adapter for %s", h.Server)
			}
			p, err := edit(a, cur, h.VirtualHost)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", h.Location(), err)
			}
			if p.After != nil {
				cur = p.After
			}
			for _, e := range p.Extra {
				cs.Edits = append(cs.Edits, e)
				servers[h.Server] = true
			}
			cs.Notes = append(cs.Notes, p.Notes...)
			if !bytes.Equal(cur, before) {
				servers[h.Server] = true
			}
		}
		if !bytes.Equal(cur, before) {
			cs.Edits = append(cs.Edits, webserver.FileEdit{
				Server: hs[0].Server, Path: f, Existed: true, Before: before, After: cur, Mode: fi.Mode().Perm(),
			})
		}
	}
	for k := range servers {
		cs.Servers = append(cs.Servers, k)
	}
	sort.Slice(cs.Servers, func(i, j int) bool { return cs.Servers[i] < cs.Servers[j] })
	// Create regular files before the symlinks pointing at them.
	sort.SliceStable(cs.Edits, func(i, j int) bool { return cs.Edits[i].Symlink == "" && cs.Edits[j].Symlink != "" })
	return cs, nil
}

// TLS returns an EditFunc that points hosts at the given certificate.
func TLS(c webserver.CertPaths, o webserver.TLSOptions) EditFunc {
	return func(a webserver.Adapter, src []byte, vh webserver.VirtualHost) (*webserver.Patch, error) {
		return a.EditTLS(src, vh, c, o)
	}
}

// Challenge returns an EditFunc that serves ACME challenges from root.
func Challenge(root string) EditFunc {
	return func(a webserver.Adapter, src []byte, vh webserver.VirtualHost) (*webserver.Patch, error) {
		return a.EditChallenge(src, vh, root)
	}
}
