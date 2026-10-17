package nginx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/bakhod1r/certx/internal/conftree"
	"github.com/bakhod1r/certx/internal/execx"
	"github.com/bakhod1r/certx/internal/webserver"
)

func (a *Adapter) Reload(ctx context.Context, inst webserver.Installation) (string, error) {
	if inst.Binary == "" {
		return "", errors.New("nginx binary not found")
	}
	args := []string{"-s", "reload"}
	if inst.ConfigPath != "" {
		args = append(args, "-c", inst.ConfigPath)
	}
	return execx.Run(ctx, inst.Binary, args...)
}

func (a *Adapter) EditTLS(src []byte, vh webserver.VirtualHost, c webserver.CertPaths, o webserver.TLSOptions) (*webserver.Patch, error) {
	n, err := findServer(src, vh.Line)
	if err != nil {
		return nil, err
	}
	var (
		edits     []splice
		add       []string
		hasCert   bool
		hasKey    bool
		hasTLS    bool
		hasPlain  bool
		hasIPv6   bool
		redirects = vh.RedirectsToHTTPS
	)
	for _, d := range n.Children {
		switch d.Name {
		case "ssl_certificate":
			hasCert = true
			edits = append(edits, splice{d.Offset, d.EndOffset, "ssl_certificate " + quote(c.Cert)})
		case "ssl_certificate_key":
			hasKey = true
			edits = append(edits, splice{d.Offset, d.EndOffset, "ssl_certificate_key " + quote(c.Key)})
		case "listen":
			l := parseListen(d.Args)
			hasTLS = hasTLS || l.TLS
			hasPlain = hasPlain || !l.TLS
			hasIPv6 = hasIPv6 || strings.HasPrefix(l.Addr, "[")
		case "ssl":
			hasTLS = hasTLS || d.Arg(0) == "on"
		}
	}
	if len(vh.Listen) > 0 && !hasTLS && !hasPlain {
		hasPlain = true // no listen directive: nginx defaults to port 80
	}
	if !hasTLS {
		add = append(add, "listen 443 ssl;")
		if hasIPv6 {
			add = append(add, "listen [::]:443 ssl;")
		}
	}
	if !hasCert {
		add = append(add, "ssl_certificate "+quote(c.Cert)+";")
	}
	if !hasKey {
		add = append(add, "ssl_certificate_key "+quote(c.Key)+";")
	}
	if o.Redirect && hasPlain && !redirects {
		add = append(add, `if ($scheme != "https") { return 301 https://$host$request_uri; }`)
	}
	if len(add) > 0 {
		edits = append(edits, insertBefore(src, n, add, webserver.ManagedMarker))
	}
	return &webserver.Patch{After: apply(src, edits)}, nil
}

func (a *Adapter) EditChallenge(src []byte, vh webserver.VirtualHost, root string) (*webserver.Patch, error) {
	n, err := findServer(src, vh.Line)
	if err != nil {
		return nil, err
	}
	loc := fmt.Sprintf(`location ^~ /.well-known/acme-challenge/ { root %s; default_type "text/plain"; }`, quote(root))
	return &webserver.Patch{After: apply(src, []splice{insertBefore(src, n, []string{loc}, webserver.ChallengeMarker)})}, nil
}

// findServer parses a single file without following includes and returns
// the server block starting at line.
func findServer(src []byte, line int) (*conftree.Node, error) {
	p := newParser("/")
	p.noInclude = true
	toks := tokenize(string(src))
	i := 0
	nodes, err := p.parseBlock("", toks, &i, false)
	if err != nil {
		return nil, err
	}
	var found *conftree.Node
	var walk func([]*conftree.Node)
	walk = func(ns []*conftree.Node) {
		for _, n := range ns {
			if found != nil || !n.Block {
				continue
			}
			if n.Name == "server" && n.Line == line {
				found = n
				return
			}
			walk(n.Children)
		}
	}
	walk(nodes)
	if found == nil {
		return nil, fmt.Errorf("server block at line %d not found (file changed since scan?)", line)
	}
	return found, nil
}

// splice replaces src[start:end] with text.
type splice struct {
	start, end int
	text       string
}

func apply(src []byte, edits []splice) []byte {
	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	out := append([]byte(nil), src...)
	for _, e := range edits {
		out = append(out[:e.start], append([]byte(e.text), out[e.end:]...)...)
	}
	return out
}

// insertBefore adds directives right before the closing "}" of n. When the
// brace sits on its own line, each directive gets its own line and a marker
// comment; otherwise they are inserted inline without comments.
func insertBefore(src []byte, n *conftree.Node, lines []string, marker string) splice {
	end := n.EndOffset
	lineStart := bytes.LastIndexByte(src[:end], '\n') + 1
	if len(bytes.TrimSpace(src[lineStart:end])) == 0 {
		indent := string(src[lineStart:end]) + childIndent(src, n)
		var b strings.Builder
		for _, l := range lines {
			b.WriteString(indent + l + " # " + marker + "\n")
		}
		return splice{lineStart, lineStart, b.String()}
	}
	return splice{end, end, strings.Join(lines, " ") + " "}
}

// childIndent guesses the indentation step used inside the block.
func childIndent(src []byte, n *conftree.Node) string {
	for _, c := range n.Children {
		ls := bytes.LastIndexByte(src[:c.Offset], '\n') + 1
		ws := src[ls:c.Offset]
		if len(bytes.TrimSpace(ws)) != 0 {
			continue
		}
		bs := bytes.LastIndexByte(src[:n.EndOffset], '\n') + 1
		closing := src[bs:n.EndOffset]
		if bytes.HasPrefix(ws, closing) && len(ws) > len(closing) {
			return string(ws[len(closing):])
		}
	}
	return "    "
}

func quote(s string) string {
	if strings.ContainsAny(s, " \t;{}#\"'") {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return s
}
