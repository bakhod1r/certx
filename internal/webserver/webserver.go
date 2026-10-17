// Package webserver defines the adapter contract implemented by every
// supported web server (Nginx, Apache) and the server-neutral data model.
package webserver

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Kind identifies a web server implementation.
type Kind string

const (
	KindNginx  Kind = "nginx"
	KindApache Kind = "apache"
)

// Listen is a single listening address of a virtual host.
type Listen struct {
	Addr string `json:"addr,omitempty"`
	Port int    `json:"port"`
	TLS  bool   `json:"tls"`
}

// VirtualHost is a server-neutral view of an Nginx server block or an Apache
// <VirtualHost> section.
type VirtualHost struct {
	Server           Kind     `json:"server"`
	File             string   `json:"file"`
	Line             int      `json:"line"`
	Enabled          bool     `json:"enabled"`
	Listen           []Listen `json:"listen"`
	Names            []string `json:"names"`
	CertFile         string   `json:"cert_file,omitempty"`
	KeyFile          string   `json:"key_file,omitempty"`
	ChainFile        string   `json:"chain_file,omitempty"`
	Webroot          string   `json:"webroot,omitempty"`
	RedirectsToHTTPS bool     `json:"redirects_to_https"`
	Protocols        []string `json:"protocols,omitempty"` // ssl_protocols / SSLProtocol in effect
	ManagedBy        string   `json:"managed_by,omitempty"`
}

// TLS reports whether any listener of the host terminates TLS.
func (v VirtualHost) TLS() bool {
	for _, l := range v.Listen {
		if l.TLS {
			return true
		}
	}
	return false
}

// Ports returns a compact description such as "80,443s".
func (v VirtualHost) Ports() string {
	seen := map[string]bool{}
	var out []string
	for _, l := range v.Listen {
		p := strconv.Itoa(l.Port)
		if l.TLS {
			p += "s"
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return strings.Join(out, ",")
}

// Location returns "file:line".
func (v VirtualHost) Location() string {
	return v.File + ":" + strconv.Itoa(v.Line)
}

// Installation describes a detected web server.
type Installation struct {
	Kind       Kind   `json:"kind"`
	Found      bool   `json:"found"`
	Binary     string `json:"binary,omitempty"`
	Version    string `json:"version,omitempty"`
	ConfigPath string `json:"config_path,omitempty"`
}

// Result is the outcome of configuration discovery.
type Result struct {
	Hosts    []VirtualHost
	Files    []string
	Warnings []string
}

// CertPaths are the files a virtual host should use for TLS.
type CertPaths struct {
	Cert string `json:"cert"` // full chain: leaf followed by intermediates
	Key  string `json:"key"`
}

// TLSOptions tune how TLS is enabled for a virtual host.
type TLSOptions struct {
	Redirect bool // add an HTTP to HTTPS redirect when none exists
}

// Patch is the result of editing the file that defines one virtual host.
type Patch struct {
	After []byte     // new content of the virtual host's file; nil when unchanged
	Extra []FileEdit // additional files to create (e.g. an Apache SSL vhost)
	Notes []string   // manual follow-ups the operator should know about
}

// FileEdit is a single file change. Before is compared with the file on disk
// right before applying so that concurrent edits are never overwritten.
type FileEdit struct {
	Server  Kind        `json:"server"`
	Path    string      `json:"path"`
	Existed bool        `json:"existed"`
	Before  []byte      `json:"-"`
	After   []byte      `json:"-"`
	Mode    fs.FileMode `json:"mode"`
	Symlink string      `json:"symlink,omitempty"` // create a symlink pointing here instead of a file
}

// ChangeSet is a reversible, diffable set of file edits.
type ChangeSet struct {
	Label   string     `json:"label"`
	Edits   []FileEdit `json:"edits"`
	Servers []Kind     `json:"servers"` // servers to validate and reload
	Notes   []string   `json:"notes,omitempty"`
}

// Empty reports whether the change set has nothing to apply.
func (c *ChangeSet) Empty() bool { return c == nil || len(c.Edits) == 0 }

// Adapter is implemented by every supported web server.
type Adapter interface {
	Kind() Kind
	Detect(ctx context.Context) Installation
	Discover(ctx context.Context, inst Installation) (*Result, error)
	Validate(ctx context.Context, inst Installation) (string, error)
	Reload(ctx context.Context, inst Installation) (string, error)

	// EditTLS returns src (the content of vh.File) changed so that vh serves
	// the given certificate.
	EditTLS(src []byte, vh VirtualHost, c CertPaths, o TLSOptions) (*Patch, error)
	// EditChallenge returns src changed so that vh serves
	// /.well-known/acme-challenge/ from root.
	EditChallenge(src []byte, vh VirtualHost, root string) (*Patch, error)
}

// ChallengeMarker tags temporary ACME challenge configuration.
const ChallengeMarker = "CertX ACME challenge (temporary)"

// ManagedMarker tags directives written by CertX.
const ManagedMarker = "managed by CertX"

// FirstExisting returns the first path that exists, or "".
func FirstExisting(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// RealPath resolves symlinks, falling back to the cleaned absolute path.
func RealPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return filepath.Clean(p)
}

// SplitAddrPort parses "addr:port", "[::]:443", "443" or "addr".
func SplitAddrPort(s string, defPort int) (string, int) {
	if p, err := strconv.Atoi(s); err == nil {
		return "", p
	}
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.HasSuffix(s, "]") {
		if p, err := strconv.Atoi(s[i+1:]); err == nil {
			return s[:i], p
		}
	}
	return s, defPort
}

// WeakProtocols returns the legacy protocols enabled by a protocol list
// (Nginx ssl_protocols or Apache SSLProtocol syntax).
func WeakProtocols(kind Kind, protocols []string) []string {
	if len(protocols) == 0 {
		return nil
	}
	legacy := []string{"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
	enabled := map[string]bool{}
	for _, p := range protocols {
		switch {
		case kind == KindApache && strings.EqualFold(p, "all"), kind == KindApache && p == "+all":
			for _, l := range legacy[1:] { // "all" excludes SSLv2 in Apache 2.4
				enabled[l] = true
			}
		case strings.HasPrefix(p, "-"):
			delete(enabled, strings.TrimPrefix(p, "-"))
		default:
			enabled[strings.TrimPrefix(p, "+")] = true
		}
	}
	var out []string
	for _, l := range legacy {
		if enabled[l] {
			out = append(out, l)
		}
	}
	return out
}

// ManagedBy guesses which client manages a certificate path.
func ManagedBy(certPath string) string {
	switch {
	case certPath == "":
		return ""
	case strings.Contains(certPath, "/etc/letsencrypt/"):
		return "certbot"
	case strings.Contains(certPath, "/var/lib/certx/"):
		return "certx"
	default:
		return "manual"
	}
}
