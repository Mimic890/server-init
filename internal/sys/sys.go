// Package sys is the only place that touches the host: commands, files and
// services. Every module goes through a System so that --dry-run can print
// what would happen instead of doing it.
package sys

import (
	"context"
	"io/fs"
	"strings"
)

// Cmd describes one command invocation.
type Cmd struct {
	Name  string
	Args  []string
	Stdin string
	Env   []string // extra KEY=VALUE pairs
}

// String renders the command the way a user would type it.
func (c Cmd) String() string {
	parts := make([]string, 0, len(c.Args)+1)
	parts = append(parts, c.Name)
	for _, a := range c.Args {
		parts = append(parts, shellQuote(a))
	}
	return strings.Join(parts, " ")
}

// Command is a shorthand for Cmd{Name: name, Args: args}.
func Command(name string, args ...string) Cmd { return Cmd{Name: name, Args: args} }

// System is the host abstraction used by all modules.
//
// Query, ReadFile, Stat, Glob and LookPath never change anything and run in
// dry-run mode too. Everything else is a change and is only printed in
// dry-run mode.
type System interface {
	DryRun() bool

	// Query runs a read-only command and returns its combined output.
	Query(ctx context.Context, name string, args ...string) (string, error)
	ReadFile(path string) ([]byte, error)
	Stat(path string) (fs.FileInfo, error)
	Glob(pattern string) ([]string, error)
	LookPath(name string) (string, error)
	Getenv(key string) string

	// Run executes a command that changes the system.
	Run(ctx context.Context, c Cmd) (string, error)
	WriteFile(path string, data []byte, perm fs.FileMode) error
	Remove(path string) error
	RemoveAll(path string) error
	MkdirAll(path string, perm fs.FileMode) error
	Chmod(path string, perm fs.FileMode) error
	Chown(path, user, group string) error
	Symlink(target, link string) error
	// CopyTree copies src to dst recursively, keeping modes and owners.
	CopyTree(src, dst string) error
}

// Exists reports whether path exists.
func Exists(s System, path string) bool {
	_, err := s.Stat(path)
	return err == nil
}

// ReadString returns the file content or "" when it does not exist.
func ReadString(s System, path string) string {
	b, err := s.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// Has reports whether a command is available.
func Has(s System, name string) bool {
	_, err := s.LookPath(name)
	return err == nil
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool {
		safe := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:=,+@%", r)
		return !safe
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
