// Package apache implements the webserver.Adapter for Apache httpd
// (Debian/Ubuntu "apache2" and RHEL/Fedora "httpd" layouts).
package apache

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bakhod1r/certx/internal/conftree"
	"github.com/bakhod1r/certx/internal/execx"
	"github.com/bakhod1r/certx/internal/webserver"
)

var (
	defaultConfigs = []string{
		"/etc/apache2/apache2.conf",
		"/etc/httpd/conf/httpd.conf",
		"/usr/local/etc/apache24/httpd.conf",
		"/usr/local/apache2/conf/httpd.conf",
		"/opt/homebrew/etc/httpd/httpd.conf",
	}
	binaries  = []string{"apache2ctl", "apachectl", "httpd", "apache2"}
	versionRe = regexp.MustCompile(`Apache/(\S+)`)
)

// Adapter discovers and manages Apache configuration.
type Adapter struct {
	ConfigPath string
	ServerRoot string
	Binary     string
}

func (a *Adapter) Kind() webserver.Kind { return webserver.KindApache }

func (a *Adapter) Detect(ctx context.Context) webserver.Installation {
	inst := webserver.Installation{Kind: webserver.KindApache, Binary: a.Binary, ConfigPath: a.ConfigPath}
	if inst.Binary == "" {
		for _, b := range binaries {
			if p, err := exec.LookPath(b); err == nil {
				inst.Binary = p
				break
			}
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

func (a *Adapter) serverRoot(conf string) string {
	if a.ServerRoot != "" {
		return a.ServerRoot
	}
	dir := filepath.Dir(conf)
	if filepath.Base(dir) == "conf" { // RHEL: /etc/httpd/conf/httpd.conf
		return filepath.Dir(dir)
	}
	return dir
}

func (a *Adapter) Discover(_ context.Context, inst webserver.Installation) (*webserver.Result, error) {
	if inst.ConfigPath == "" {
		return nil, errors.New("apache: configuration file not found")
	}
	root := a.serverRoot(inst.ConfigPath)
	p := newParser(root, a.ServerRoot != "")
	nodes, err := p.parseFile(inst.ConfigPath)
	if err != nil {
		return nil, err
	}
	res := &webserver.Result{}
	collect(nodes, p.root, true, &res.Hosts)
	if global := globalProtocols(nodes); global != nil {
		for i := range res.Hosts {
			if res.Hosts[i].TLS() && res.Hosts[i].Protocols == nil {
				res.Hosts[i].Protocols = global
			}
		}
	}

	// Debian layout: sites-available entries not linked into sites-enabled.
	available, _ := filepath.Glob(filepath.Join(p.root, "sites-available", "*.conf"))
	sort.Strings(available)
	for _, f := range available {
		if p.files[webserver.RealPath(f)] {
			continue
		}
		sub := newParser(p.root, true)
		ns, err := sub.parseFile(f)
		if err != nil {
			p.warn("%v", err)
			continue
		}
		collect(ns, p.root, false, &res.Hosts)
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
		return "", errors.New("apache binary not found")
	}
	args := []string{"-t"}
	if base := filepath.Base(inst.Binary); (base == "httpd" || base == "apache2") && inst.ConfigPath != "" {
		args = append(args, "-f", inst.ConfigPath)
	}
	return execx.Run(ctx, inst.Binary, args...)
}

func collect(nodes []*conftree.Node, root string, enabled bool, out *[]webserver.VirtualHost) {
	for _, n := range nodes {
		if !n.Block {
			continue
		}
		if n.Is("VirtualHost") {
			*out = append(*out, vhostToHost(n, root, enabled))
			continue
		}
		collect(n.Children, root, enabled, out) // IfModule, IfDefine, ...
	}
}

func vhostToHost(n *conftree.Node, root string, enabled bool) webserver.VirtualHost {
	vh := webserver.VirtualHost{Server: webserver.KindApache, File: n.File, Line: n.Line, Enabled: enabled}
	for _, a := range n.Args {
		addr, port := webserver.SplitAddrPort(a, 80)
		vh.Listen = append(vh.Listen, webserver.Listen{Addr: addr, Port: port})
	}
	if len(vh.Listen) == 0 {
		vh.Listen = []webserver.Listen{{Addr: "*", Port: 80}}
	}
	sslOn := false
	var walk func([]*conftree.Node)
	walk = func(ds []*conftree.Node) {
		for _, d := range ds {
			if d.Block {
				walk(d.Children)
				continue
			}
			switch strings.ToLower(d.Name) {
			case "servername":
				vh.Names = append([]string{cleanName(d.Arg(0))}, vh.Names...)
			case "serveralias":
				for _, a := range d.Args {
					vh.Names = append(vh.Names, cleanName(a))
				}
			case "sslengine":
				sslOn = strings.EqualFold(d.Arg(0), "on")
			case "sslcertificatefile":
				vh.CertFile = resolve(root, d.Arg(0))
			case "sslcertificatekeyfile":
				vh.KeyFile = resolve(root, d.Arg(0))
			case "sslcertificatechainfile":
				vh.ChainFile = resolve(root, d.Arg(0))
			case "documentroot":
				vh.Webroot = d.Arg(0)
			case "sslprotocol":
				vh.Protocols = d.Args
			case "redirect", "redirectpermanent", "redirectmatch", "rewriterule":
				if strings.Contains(strings.Join(d.Args, " "), "https://") {
					vh.RedirectsToHTTPS = true
				}
			}
		}
	}
	walk(n.Children)
	if sslOn {
		for i := range vh.Listen {
			vh.Listen[i].TLS = true
		}
	}
	// Apache uses the key from the certificate file when no key file is set.
	if vh.CertFile != "" && vh.KeyFile == "" {
		vh.KeyFile = vh.CertFile
	}
	vh.ManagedBy = webserver.ManagedBy(vh.CertFile)
	return vh
}

// globalProtocols returns the last server-wide SSLProtocol directive.
func globalProtocols(nodes []*conftree.Node) []string {
	var out []string
	for _, n := range nodes {
		switch {
		case n.Block && n.Is("VirtualHost"):
		case n.Block:
			if p := globalProtocols(n.Children); p != nil {
				out = p
			}
		case n.Is("SSLProtocol"):
			out = n.Args
		}
	}
	return out
}

func cleanName(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if addr, port := webserver.SplitAddrPort(s, 0); port != 0 && addr != "" {
		return addr
	}
	return s
}

func resolve(root, p string) string {
	if p == "" || filepath.IsAbs(p) || strings.Contains(p, "${") {
		return p
	}
	return filepath.Join(root, p)
}
