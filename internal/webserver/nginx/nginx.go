// Package nginx implements the webserver.Adapter for Nginx.
package nginx

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bakhod1r/certx/internal/conftree"
	"github.com/bakhod1r/certx/internal/execx"
	"github.com/bakhod1r/certx/internal/webserver"
)

var defaultConfigs = []string{
	"/etc/nginx/nginx.conf",
	"/usr/local/nginx/conf/nginx.conf",
	"/usr/local/etc/nginx/nginx.conf",
	"/opt/homebrew/etc/nginx/nginx.conf",
}

var versionRe = regexp.MustCompile(`nginx/(\S+)`)

// Adapter discovers and manages Nginx configuration.
type Adapter struct {
	ConfigPath string
	Binary     string
}

func (a *Adapter) Kind() webserver.Kind { return webserver.KindNginx }

func (a *Adapter) Detect(ctx context.Context) webserver.Installation {
	inst := webserver.Installation{Kind: webserver.KindNginx, Binary: a.Binary, ConfigPath: a.ConfigPath}
	if inst.Binary == "" {
		if p, err := exec.LookPath("nginx"); err == nil {
			inst.Binary = p
		}
	}
	if inst.ConfigPath == "" {
		inst.ConfigPath = webserver.FirstExisting(defaultConfigs)
	}
	if inst.Binary != "" {
		out, _ := execx.Run(ctx, inst.Binary, "-v")
		if m := versionRe.FindStringSubmatch(out); m != nil {
			inst.Version = m[1]
		}
	}
	inst.Found = inst.Binary != "" || inst.ConfigPath != ""
	return inst
}

func (a *Adapter) Discover(_ context.Context, inst webserver.Installation) (*webserver.Result, error) {
	if inst.ConfigPath == "" {
		return nil, errors.New("nginx: configuration file not found")
	}
	prefix := filepath.Dir(inst.ConfigPath)
	p := newParser(prefix)
	nodes, err := p.parseFile(inst.ConfigPath)
	if err != nil {
		return nil, err
	}
	res := &webserver.Result{}
	collect(nodes, prefix, false, inherited{}, true, &res.Hosts)

	// Sites that exist in sites-available but are not reachable from nginx.conf.
	available, _ := filepath.Glob(filepath.Join(prefix, "sites-available", "*"))
	sort.Strings(available)
	for _, f := range available {
		if p.files[webserver.RealPath(f)] {
			continue
		}
		if fi, err := os.Stat(f); err != nil || fi.IsDir() {
			continue
		}
		sub := newParser(prefix)
		ns, err := sub.parseFile(f)
		if err != nil {
			p.warn("%v", err)
			continue
		}
		collect(ns, prefix, true, inherited{}, false, &res.Hosts)
	}

	for f := range p.files {
		res.Files = append(res.Files, f)
	}
	sort.Strings(res.Files)
	res.Warnings = p.warnings
	return res, nil
}

func (a *Adapter) Validate(ctx context.Context, inst webserver.Installation) (string, error) {
	if inst.Binary == "" {
		return "", errors.New("nginx binary not found")
	}
	args := []string{"-t"}
	if inst.ConfigPath != "" {
		args = append(args, "-c", inst.ConfigPath)
	}
	return execx.Run(ctx, inst.Binary, args...)
}

type inherited struct{ cert, key string }

func collect(nodes []*conftree.Node, prefix string, inHTTP bool, inh inherited, enabled bool, out *[]webserver.VirtualHost) {
	if inHTTP {
		for _, n := range nodes {
			switch n.Name {
			case "ssl_certificate":
				inh.cert = resolve(prefix, n.Arg(0))
			case "ssl_certificate_key":
				inh.key = resolve(prefix, n.Arg(0))
			}
		}
	}
	for _, n := range nodes {
		switch {
		case n.Name == "http" && n.Block:
			collect(n.Children, prefix, true, inh, enabled, out)
		case n.Name == "server" && n.Block && inHTTP:
			*out = append(*out, serverToHost(n, prefix, inh, enabled))
		}
	}
}

func serverToHost(n *conftree.Node, prefix string, inh inherited, enabled bool) webserver.VirtualHost {
	vh := webserver.VirtualHost{Server: webserver.KindNginx, File: n.File, Line: n.Line, Enabled: enabled}
	sslOn := false
	for _, d := range n.Children {
		switch d.Name {
		case "listen":
			vh.Listen = append(vh.Listen, parseListen(d.Args))
		case "server_name":
			for _, a := range d.Args {
				if a != "" && a != `""` {
					vh.Names = append(vh.Names, a)
				}
			}
		case "ssl_certificate":
			vh.CertFile = resolve(prefix, d.Arg(0))
		case "ssl_certificate_key":
			vh.KeyFile = resolve(prefix, d.Arg(0))
		case "ssl":
			sslOn = d.Arg(0) == "on"
		case "root":
			vh.Webroot = d.Arg(0)
		}
	}
	vh.RedirectsToHTTPS = redirects(n.Children)
	if len(vh.Listen) == 0 {
		vh.Listen = []webserver.Listen{{Port: 80}}
	}
	if sslOn {
		for i := range vh.Listen {
			vh.Listen[i].TLS = true
		}
	}
	// http-level certificates only matter for TLS listeners.
	if vh.TLS() {
		if vh.CertFile == "" {
			vh.CertFile = inh.cert
		}
		if vh.KeyFile == "" {
			vh.KeyFile = inh.key
		}
	}
	vh.ManagedBy = webserver.ManagedBy(vh.CertFile)
	return vh
}

func redirects(nodes []*conftree.Node) bool {
	for _, d := range nodes {
		if (d.Name == "return" || d.Name == "rewrite") && strings.Contains(strings.Join(d.Args, " "), "https://") {
			return true
		}
		if d.Block && d.Name == "location" && d.Arg(0) == "/" && redirects(d.Children) {
			return true
		}
		if d.Block && d.Name == "if" && redirects(d.Children) {
			return true
		}
	}
	return false
}

func parseListen(args []string) webserver.Listen {
	if len(args) == 0 {
		return webserver.Listen{Port: 80}
	}
	addr, port := webserver.SplitAddrPort(args[0], 80)
	l := webserver.Listen{Addr: addr, Port: port}
	for _, f := range args[1:] {
		if f == "ssl" || f == "quic" {
			l.TLS = true
		}
	}
	return l
}

func resolve(prefix, p string) string {
	if p == "" || filepath.IsAbs(p) || strings.HasPrefix(p, "data:") || strings.Contains(p, "$") {
		return p
	}
	return filepath.Join(prefix, p)
}
