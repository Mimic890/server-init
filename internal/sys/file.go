package sys

import (
	"strings"

	udiff "github.com/aymanbagabas/go-udiff"
)

// Diff returns a unified diff between the old and updated content of path.
// An empty string means "no change".
func Diff(path, old, updated string) string {
	if old == updated {
		return ""
	}
	from := "a" + path
	if old == "" {
		from = "/dev/null"
	}
	return udiff.Unified(from, "b"+path, old, updated)
}

// Block markers used for the few main config files that have no drop-in
// directory (fstab, ufw after.rules, ...).
const (
	MarkerBegin = "# BEGIN server-init"
	MarkerEnd   = "# END server-init"
)

// MarkedBlock wraps body in begin/end markers that carry a name, so several
// independent blocks can live in one file.
func MarkedBlock(name, body string) string {
	body = strings.TrimRight(body, "\n")
	return MarkerBegin + " " + name + "\n" + body + "\n" + MarkerEnd + " " + name + "\n"
}

// SetBlock replaces the named marked block in content with block (already
// wrapped by MarkedBlock). If the block is missing it is inserted before the
// first line that starts with insertBefore, or appended when insertBefore is
// empty or not found. An empty block removes the existing one.
func SetBlock(content, name, block, insertBefore string) string {
	begin := MarkerBegin + " " + name + "\n"
	end := MarkerEnd + " " + name + "\n"
	if i := strings.Index(content, begin); i >= 0 {
		if j := strings.Index(content[i:], end); j >= 0 {
			return content[:i] + block + content[i+j+len(end):]
		}
	}
	if block == "" {
		return content
	}
	if insertBefore != "" {
		lines := strings.SplitAfter(content, "\n")
		for i, l := range lines {
			if strings.HasPrefix(l, insertBefore) {
				return strings.Join(lines[:i], "") + block + strings.Join(lines[i:], "")
			}
		}
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + block
}

// HasBlock reports whether the named block is present.
func HasBlock(content, name string) bool {
	return strings.Contains(content, MarkerBegin+" "+name+"\n")
}
