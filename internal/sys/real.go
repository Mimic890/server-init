package sys

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Executor runs a command and returns its combined output.
type Executor func(ctx context.Context, c Cmd) (string, error)

// Real is the System that really changes the host.
type Real struct {
	// Root prefixes every file path. Empty means "/". Tests point it to a
	// temporary directory.
	Root string
	// Exec runs commands. Nil means os/exec.
	Exec Executor
	// SkipChown turns Chown into a no-op (tests without root).
	SkipChown bool
	// OnCommand is called after every command (for logging).
	OnCommand func(c Cmd, out string, err error)
	// Look overrides LookPath when set (tests).
	Look func(name string) (string, error)
	// Env overrides Getenv when set (tests).
	Env map[string]string
}

// NewReal returns a System for the live host.
func NewReal() *Real { return &Real{} }

func (r *Real) DryRun() bool { return false }

func (r *Real) p(path string) string {
	if r.Root == "" {
		return path
	}
	return filepath.Join(r.Root, path)
}

func (r *Real) exec(ctx context.Context, c Cmd) (string, error) {
	run := r.Exec
	if run == nil {
		run = OSExec
	}
	out, err := run(ctx, c)
	if r.OnCommand != nil {
		r.OnCommand(c, out, err)
	}
	return out, err
}

// OSExec runs a command with os/exec. Output is not localized and apt never
// asks questions.
func OSExec(ctx context.Context, c Cmd) (string, error) {
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a")
	cmd.Env = append(cmd.Env, c.Env...)
	if c.Stdin != "" {
		cmd.Stdin = strings.NewReader(c.Stdin)
	}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	out := buf.String()
	if err != nil {
		msg := strings.TrimSpace(out)
		if len(msg) > 2000 {
			msg = "..." + msg[len(msg)-2000:]
		}
		if msg != "" {
			err = fmt.Errorf("%s: %w: %s", c.String(), err, msg)
		} else {
			err = fmt.Errorf("%s: %w", c.String(), err)
		}
	}
	return out, err
}

func (r *Real) Query(ctx context.Context, name string, args ...string) (string, error) {
	return r.exec(ctx, Cmd{Name: name, Args: args})
}

func (r *Real) Run(ctx context.Context, c Cmd) (string, error) { return r.exec(ctx, c) }

func (r *Real) ReadFile(path string) ([]byte, error) { return os.ReadFile(r.p(path)) }

func (r *Real) Stat(path string) (fs.FileInfo, error) { return os.Stat(r.p(path)) }

func (r *Real) Glob(pattern string) ([]string, error) {
	m, err := filepath.Glob(r.p(pattern))
	if err != nil || r.Root == "" {
		return m, err
	}
	for i := range m {
		m[i] = "/" + strings.TrimPrefix(strings.TrimPrefix(m[i], r.Root), "/")
	}
	return m, nil
}

func (r *Real) LookPath(name string) (string, error) {
	if r.Look != nil {
		return r.Look(name)
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: %w", name, exec.ErrNotFound)
}

func (r *Real) Getenv(key string) string {
	if r.Env != nil {
		return r.Env[key]
	}
	return os.Getenv(key)
}

// WriteFile writes atomically (temp file + rename) so a crash never leaves a
// half-written config behind. An existing file keeps its owner.
func (r *Real) WriteFile(path string, data []byte, perm fs.FileMode) error {
	full := r.p(path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	var uid, gid = -1, -1
	if st, err := os.Stat(full); err == nil {
		if s, ok := st.Sys().(*syscall.Stat_t); ok {
			uid, gid = int(s.Uid), int(s.Gid)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(full), "."+filepath.Base(full)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), perm); err != nil {
		return err
	}
	if uid >= 0 && !r.SkipChown {
		_ = os.Chown(tmp.Name(), uid, gid)
	}
	if err := os.Rename(tmp.Name(), full); err != nil {
		// Bind-mounted files (e.g. /etc/hosts in containers) cannot be
		// replaced; write them in place instead.
		if errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.EXDEV) {
			return os.WriteFile(full, data, perm)
		}
		return err
	}
	return nil
}

func (r *Real) Remove(path string) error {
	err := os.Remove(r.p(path))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (r *Real) RemoveAll(path string) error { return os.RemoveAll(r.p(path)) }

func (r *Real) MkdirAll(path string, perm fs.FileMode) error {
	if err := os.MkdirAll(r.p(path), perm); err != nil {
		return err
	}
	return os.Chmod(r.p(path), perm)
}

func (r *Real) Chmod(path string, perm fs.FileMode) error { return os.Chmod(r.p(path), perm) }

func (r *Real) Chown(path, owner, group string) error {
	if r.SkipChown {
		return nil
	}
	uid, gid := -1, -1
	if owner != "" {
		u, err := user.Lookup(owner)
		if err != nil {
			return err
		}
		uid, _ = strconv.Atoi(u.Uid)
	}
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			return err
		}
		gid, _ = strconv.Atoi(g.Gid)
	}
	return os.Lchown(r.p(path), uid, gid)
}

func (r *Real) Symlink(target, link string) error {
	full := r.p(link)
	_ = os.Remove(full)
	return os.Symlink(target, full)
}

func (r *Real) CopyTree(src, dst string) error {
	return copyTree(r.p(src), r.p(dst), !r.SkipChown)
}

func copyTree(src, dst string, chown bool) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Symlink(link, target); err != nil {
				return err
			}
		case info.IsDir():
			if err := os.MkdirAll(target, info.Mode().Perm()); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			if err := copyFile(path, target, info.Mode().Perm()); err != nil {
				return err
			}
		default:
			return nil // sockets, devices: skip
		}
		if chown {
			if s, ok := info.Sys().(*syscall.Stat_t); ok {
				_ = os.Lchown(target, int(s.Uid), int(s.Gid))
			}
		}
		if !info.IsDir() && info.Mode()&fs.ModeSymlink == 0 {
			_ = os.Chmod(target, info.Mode().Perm())
		}
		return nil
	})
}

func copyFile(src, dst string, perm fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
