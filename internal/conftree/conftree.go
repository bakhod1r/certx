// Package conftree holds a server-neutral configuration syntax tree shared by
// the Nginx and Apache parsers.
package conftree

import "strings"

// Node is a single directive or block (Nginx "server { }", Apache "<VirtualHost>").
type Node struct {
	Name     string
	Args     []string
	Block    bool
	Children []*Node
	File     string
	Line     int
}

// Arg returns the i-th argument or an empty string.
func (n *Node) Arg(i int) string {
	if i < len(n.Args) {
		return n.Args[i]
	}
	return ""
}

// Is reports whether the node name matches name, ignoring case.
func (n *Node) Is(name string) bool {
	return strings.EqualFold(n.Name, name)
}
