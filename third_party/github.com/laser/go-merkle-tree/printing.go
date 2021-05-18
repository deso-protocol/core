package merkletree

import (
	"fmt"
	"strings"
)

func (m *Proof) ToString(f HashToStrFunc) string {
	var lines []string

	parts := m.PathToRoot
	if len(parts) == 0 {
		return "" // checksums don't match up with receiver
	}

	lines = append(lines, fmt.Sprintf("route from %s (leaf) to root:", f(m.LeafHash)))
	lines = append(lines, "")

	var prev = m.LeafHash
	var curr []byte
	for i := 0; i < len(parts); i++ {
		if parts[i].IsRight {
			curr = m.HashFunc(false, append(prev, parts[i].Hash...))
			lines = append(lines, fmt.Sprintf("%s + %s = %s", f(prev), f(parts[i].Hash), f(curr)))
		} else {
			curr = m.HashFunc(false, append(parts[i].Hash, prev...))
			lines = append(lines, fmt.Sprintf("%s + %s = %s", f(parts[i].Hash), f(prev), f(curr)))
		}
		prev = curr
	}

	return strings.Join(lines, "\n")
}

func (t *Tree) ToString(f HashToStrFunc, n int) string {
	return t.Root.ToString(f, n)
}

func (l *Leaf) ToString(f HashToStrFunc, n int) string {
	return fmt.Sprintf("\n"+indent(n, "(L root: %s)"), f(l.Hash))
}

func (b *Branch) ToString(f HashToStrFunc, n int) string {
	c := f(b.Hash)
	l := b.Left.ToString(f, n+2)
	r := b.Right.ToString(f, n+2)

	return fmt.Sprintf("\n"+indent(n, "(B root: %s %s %s)"), c, l, r)
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// HELPERS
//////////

func indent(spaces int, orig string) string {
	str := ""
	for i := 0; i < spaces; i++ {
		str += " "
	}

	return str + orig
}
