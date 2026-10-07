// Package systest provides a sandboxed sys.System for tests: files live in a
// temporary directory, commands are answered by a stub.
package systest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mimic890/server-init/internal/sys"
)

// Host is a fake host.
type Host struct {
	*sys.Real
	T *testing.T

	mu sync.Mutex
	// Cmds are all commands run (Query and Run), as strings.
	Cmds []string
	// Responses maps a command prefix ("ss -H -ltn") to its output. A value
	// starting with "ERR:" makes the command fail.
	Responses map[string]string
	// Tools that LookPath finds.
	Tools map[string]bool
	// Hook, when set, answers commands first (handled=true).
	Hook func(line string) (out string, err error, handled bool)
}

// New returns a fake host rooted in a temp directory.
func New(t *testing.T) *Host {
	h := &Host{T: t, Responses: map[string]string{}, Tools: map[string]bool{}}
	h.Real = &sys.Real{
		Root:      t.TempDir(),
		SkipChown: true,
		Env:       map[string]string{},
	}
	h.Exec = h.exec
	h.Look = func(name string) (string, error) {
		if h.Tools[name] {
			return "/usr/bin/" + name, nil
		}
		return "", fmt.Errorf("%s: not found", name)
	}
	return h
}

func (h *Host) exec(_ context.Context, c sys.Cmd) (string, error) {
	line := c.String()
	h.mu.Lock()
	h.Cmds = append(h.Cmds, line)
	hook := h.Hook
	h.mu.Unlock()
	if hook != nil {
		if out, err, ok := hook(line); ok {
			return out, err
		}
	}
	h.mu.Lock()
	best := ""
	for k := range h.Responses {
		if strings.HasPrefix(line, k) && len(k) > len(best) {
			best = k
		}
	}
	h.mu.Unlock()
	if best == "" {
		return "", nil
	}
	out := h.Responses[best]
	if rest, ok := strings.CutPrefix(out, "ERR:"); ok {
		return rest, errors.New("exit status 1")
	}
	return out, nil
}

// On sets the output of commands starting with prefix.
func (h *Host) On(prefix, out string) { h.Responses[prefix] = out }

// Fail makes commands starting with prefix fail.
func (h *Host) Fail(prefix string) { h.Responses[prefix] = "ERR:" }

// Write creates a file in the sandbox.
func (h *Host) Write(path, content string) {
	h.T.Helper()
	full := filepath.Join(h.Root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		h.T.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		h.T.Fatal(err)
	}
}

// Read returns a sandbox file ("" if missing).
func (h *Host) Read(path string) string {
	b, _ := os.ReadFile(filepath.Join(h.Root, path))
	return string(b)
}

// Exists reports whether a sandbox file exists.
func (h *Host) Exists(path string) bool {
	_, err := os.Stat(filepath.Join(h.Root, path))
	return err == nil
}

// Ran reports whether a command starting with prefix was run.
func (h *Host) Ran(prefix string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.Cmds {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// Reset forgets recorded commands.
func (h *Host) Reset() {
	h.mu.Lock()
	h.Cmds = nil
	h.mu.Unlock()
}

// Count returns how many commands started with prefix.
func (h *Host) Count(prefix string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, c := range h.Cmds {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}
