package apache

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bakhod1r/certx/internal/conftree"
	"github.com/bakhod1r/certx/internal/webserver"
)

type line struct {
	text string
	num  int
}

// logicalLines joins "\" continuations and drops comments and blank lines.
func logicalLines(src string) []line {
	var out []line
	raw := strings.Split(src, "\n")
	for i := 0; i < len(raw); i++ {
		start := i + 1
		text := strings.TrimRight(raw[i], " \t\r")
		for strings.HasSuffix(text, "\\") && i+1 < len(raw) {
			i++
			text = strings.TrimRight(strings.TrimSuffix(text, "\\"), " \t") + " " + strings.TrimSpace(strings.TrimRight(raw[i], "\r"))
		}
		text = strings.TrimSpace(text)
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		out = append(out, line{text: text, num: start})
	}
	return out
}

// splitArgs splits a directive line honouring single and double quotes.
func splitArgs(s string) []string {
	var (
		out   []string
		b     strings.Builder
		quote byte
		have  bool
	)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0 && c == '\\' && i+1 < len(s):
			i++
			b.WriteByte(s[i])
		case quote != 0 && c == quote:
			quote = 0
		case quote == 0 && (c == '"' || c == '\''):
			quote, have = c, true
		case quote == 0 && (c == ' ' || c == '\t'):
			if have || b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
				have = false
			}
		default:
			b.WriteByte(c)
		}
	}
	if have || b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

type parser struct {
	root      string
	fixedRoot bool
	files     map[string]bool
	stack     map[string]bool
	warnings  []string
}

func newParser(root string, fixed bool) *parser {
	return &parser{root: root, fixedRoot: fixed, files: map[string]bool{}, stack: map[string]bool{}}
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

	lines := logicalLines(string(data))
	i := 0
	return p.parseSection(path, lines, &i, "")
}

func (p *parser) parseSection(file string, lines []line, i *int, closing string) ([]*conftree.Node, error) {
	var nodes []*conftree.Node
	for *i < len(lines) {
		l := lines[*i]
		*i++
		switch {
		case strings.HasPrefix(l.text, "</"):
			name := strings.TrimSpace(strings.TrimSuffix(l.text[2:], ">"))
			if closing == "" || !strings.EqualFold(name, closing) {
				return nil, fmt.Errorf("%s:%d: unexpected </%s>", file, l.num, name)
			}
			return nodes, nil
		case strings.HasPrefix(l.text, "<"):
			fields := splitArgs(strings.TrimSpace(strings.TrimSuffix(l.text[1:], ">")))
			if len(fields) == 0 {
				return nil, fmt.Errorf("%s:%d: empty section", file, l.num)
			}
			n := &conftree.Node{Name: fields[0], Args: fields[1:], Block: true, File: file, Line: l.num}
			children, err := p.parseSection(file, lines, i, fields[0])
			if err != nil {
				return nil, err
			}
			n.Children = children
			nodes = append(nodes, n)
		default:
			fields := splitArgs(l.text)
			if len(fields) == 0 {
				continue
			}
			n := &conftree.Node{Name: fields[0], Args: fields[1:], File: file, Line: l.num}
			if n.Is("ServerRoot") && !p.fixedRoot && n.Arg(0) != "" {
				if fi, err := os.Stat(n.Arg(0)); err == nil && fi.IsDir() {
					p.root = n.Arg(0)
				}
			}
			if n.Is("Include") || n.Is("IncludeOptional") {
				nodes = append(nodes, p.include(n, n.Is("IncludeOptional"))...)
				continue
			}
			nodes = append(nodes, n)
		}
	}
	if closing != "" {
		return nil, fmt.Errorf("%s: missing </%s>", file, closing)
	}
	return nodes, nil
}

func (p *parser) include(n *conftree.Node, optional bool) []*conftree.Node {
	pattern := n.Arg(0)
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(p.root, pattern)
	}
	if fi, err := os.Stat(pattern); err == nil && fi.IsDir() {
		pattern = filepath.Join(pattern, "*")
	}
	matches, err := filepath.Glob(pattern)
	if err != nil {
		p.warn("%s:%d: %s %s: %v", n.File, n.Line, n.Name, n.Arg(0), err)
		return nil
	}
	if len(matches) == 0 && !optional {
		p.warn("%s:%d: %s %s: no matching files", n.File, n.Line, n.Name, n.Arg(0))
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
