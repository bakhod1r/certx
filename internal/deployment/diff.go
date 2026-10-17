package deployment

import (
	"fmt"
	"strings"

	"github.com/bakhod1r/certx/internal/webserver"
)

const contextLines = 3

// Diff renders a ChangeSet as unified diffs.
func Diff(cs *webserver.ChangeSet) string {
	var b strings.Builder
	for _, e := range cs.Edits {
		switch {
		case e.Symlink != "":
			fmt.Fprintf(&b, "+++ %s -> %s (new symlink)\n", e.Path, e.Symlink)
		case !e.Existed:
			fmt.Fprintf(&b, "--- /dev/null\n+++ %s (new file)\n", e.Path)
			b.WriteString(unified(nil, lines(e.After)))
		default:
			fmt.Fprintf(&b, "--- %s\n+++ %s\n", e.Path, e.Path)
			b.WriteString(unified(lines(e.Before), lines(e.After)))
		}
	}
	return b.String()
}

func lines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

type op struct {
	kind byte // ' ', '-', '+'
	text string
	a, b int // 1-based line numbers in old/new
}

// unified computes an LCS-based line diff with three lines of context.
func unified(a, b []string) string {
	ops := diffOps(a, b)
	var out strings.Builder
	for i := 0; i < len(ops); {
		if ops[i].kind == ' ' {
			i++
			continue
		}
		start := max(0, i-contextLines)
		end := i
		for j := i; j < len(ops); j++ {
			if ops[j].kind != ' ' {
				end = j
			} else if j-end > 2*contextLines {
				break
			}
		}
		end = min(len(ops), end+contextLines+1)
		hunk := ops[start:end]
		aStart, bStart, aLen, bLen := 0, 0, 0, 0
		for _, o := range hunk {
			if o.kind != '+' {
				if aStart == 0 {
					aStart = o.a
				}
				aLen++
			}
			if o.kind != '-' {
				if bStart == 0 {
					bStart = o.b
				}
				bLen++
			}
		}
		fmt.Fprintf(&out, "@@ -%d,%d +%d,%d @@\n", aStart, aLen, bStart, bLen)
		for _, o := range hunk {
			out.WriteString(string(o.kind) + o.text + "\n")
		}
		i = end
	}
	return out.String()
}

func diffOps(a, b []string) []op {
	n, m := len(a), len(b)
	lcs := make([][]int32, n+1)
	for i := range lcs {
		lcs[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var ops []op
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && a[i] == b[j]:
			ops = append(ops, op{' ', a[i], i + 1, j + 1})
			i++
			j++
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			ops = append(ops, op{'-', a[i], i + 1, j + 1})
			i++
		default:
			ops = append(ops, op{'+', b[j], i + 1, j + 1})
			j++
		}
	}
	return ops
}
