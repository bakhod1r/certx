package nginx

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bakhod1r/certx/internal/conftree"
	"github.com/bakhod1r/certx/internal/webserver"
)

type token struct {
	text   string
	line   int
	off    int
	quoted bool
}

func tokenize(src string) []token {
	var toks []token
	line := 1
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == ';' || c == '{' || c == '}':
			toks = append(toks, token{text: string(c), line: line, off: i})
			i++
		case c == '"' || c == '\'':
			start, off := line, i
			var b strings.Builder
			for i++; i < len(src) && src[i] != c; i++ {
				// Like nginx, only \\ and an escaped quote drop the backslash.
				if src[i] == '\\' && i+1 < len(src) && (src[i+1] == c || src[i+1] == '\\') {
					i++
				}
				if src[i] == '\n' {
					line++
				}
				b.WriteByte(src[i])
			}
			i++
			toks = append(toks, token{text: b.String(), line: start, off: off, quoted: true})
		default:
			start := i
			for i < len(src) && !strings.ContainsRune(" \t\r\n;{}", rune(src[i])) {
				// ${var} is part of the word, not a block.
				if src[i] == '$' && i+1 < len(src) && src[i+1] == '{' {
					if end := strings.IndexByte(src[i:], '}'); end > 0 {
						i += end + 1
						continue
					}
				}
				i++
			}
			toks = append(toks, token{text: src[start:i], line: line, off: start})
		}
	}
	return toks
}

type parser struct {
	prefix    string
	noInclude bool // keep include directives as nodes (used when editing a single file)
	files     map[string]bool
	stack     map[string]bool
	warnings  []string
}

func newParser(prefix string) *parser {
	return &parser{prefix: prefix, files: map[string]bool{}, stack: map[string]bool{}}
}

func (p *parser) warn(format string, args ...any) {
	p.warnings = append(p.warnings, fmt.Sprintf(format, args...))
}

func (p *parser) parseFile(path string) ([]*conftree.Node, error) {
	real := webserver.RealPath(path)
	if p.stack[real] {
		return nil, fmt.Errorf("%s: include cycle", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p.stack[real] = true
	defer delete(p.stack, real)
	p.files[real] = true

	toks := tokenize(string(data))
	i := 0
	return p.parseBlock(path, toks, &i, false)
}

func (p *parser) parseBlock(file string, toks []token, i *int, nested bool) ([]*conftree.Node, error) {
	nodes, _, err := p.parseBlockEnd(file, toks, i, nested)
	return nodes, err
}

// parseBlockEnd parses directives until the matching "}" and returns it.
func (p *parser) parseBlockEnd(file string, toks []token, i *int, nested bool) ([]*conftree.Node, token, error) {
	var nodes []*conftree.Node
	fail := func(err error) ([]*conftree.Node, token, error) { return nil, token{}, err }
	for *i < len(toks) {
		t := toks[*i]
		if !t.quoted && t.text == "}" {
			if !nested {
				return fail(fmt.Errorf("%s:%d: unexpected \"}\"", file, t.line))
			}
			*i++
			return nodes, t, nil
		}
		if !t.quoted && (t.text == ";" || t.text == "{") {
			return fail(fmt.Errorf("%s:%d: unexpected %q", file, t.line, t.text))
		}
		n := &conftree.Node{Name: t.text, File: file, Line: t.line, Offset: t.off}
		*i++
	args:
		for {
			if *i >= len(toks) {
				return fail(fmt.Errorf("%s:%d: unexpected end of file", file, n.Line))
			}
			t = toks[*i]
			switch {
			case !t.quoted && t.text == ";":
				*i++
				n.EndLine, n.EndOffset = t.line, t.off
				break args
			case !t.quoted && t.text == "{":
				*i++
				n.Block = true
				children, end, err := p.parseBlockEnd(file, toks, i, true)
				if err != nil {
					return fail(err)
				}
				n.Children = children
				n.EndLine, n.EndOffset = end.line, end.off
				break args
			case !t.quoted && t.text == "}":
				return fail(fmt.Errorf("%s:%d: unexpected \"}\"", file, t.line))
			default:
				n.Args = append(n.Args, t.text)
				*i++
			}
		}
		if n.Name == "include" && !n.Block && !p.noInclude {
			nodes = append(nodes, p.include(n)...)
			continue
		}
		nodes = append(nodes, n)
	}
	if nested {
		return fail(fmt.Errorf("%s: unexpected end of file, expecting \"}\"", file))
	}
	return nodes, token{}, nil
}

func (p *parser) include(n *conftree.Node) []*conftree.Node {
	pattern := n.Arg(0)
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(p.prefix, pattern)
	}
	matches, err := filepath.Glob(pattern)
	if err != nil {
		p.warn("%s:%d: include %s: %v", n.File, n.Line, n.Arg(0), err)
		return nil
	}
	if len(matches) == 0 && !strings.ContainsAny(pattern, "*?[") {
		p.warn("%s:%d: include %s: file not found", n.File, n.Line, n.Arg(0))
	}
	sort.Strings(matches)
	var out []*conftree.Node
	for _, m := range matches {
		fi, err := os.Stat(m)
		if err != nil {
			p.warn("%s: broken symlink or unreadable file: %v", m, err)
			continue
		}
		if fi.IsDir() {
			continue
		}
		nodes, err := p.parseFile(m)
		if err != nil {
			p.warn("%v", err)
			continue
		}
		out = append(out, nodes...)
	}
	return out
}
