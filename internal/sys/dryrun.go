package sys

import (
	"context"
	"fmt"
	"io/fs"
	"sync"
)

// DryRun wraps a System: reads go to the wrapped System, changes are only
// recorded. Nothing on the host is modified.
type DryRun struct {
	Base System
	// Record receives one human-readable line (or diff) per change.
	Record func(action string)

	mu    sync.Mutex
	files map[string][]byte // what would have been written, so later reads see it
	gone  map[string]bool
}

// NewDryRun wraps base.
func NewDryRun(base System, record func(string)) *DryRun {
	return &DryRun{Base: base, Record: record, files: map[string][]byte{}, gone: map[string]bool{}}
}

func (d *DryRun) DryRun() bool { return true }

func (d *DryRun) note(format string, args ...any) {
	if d.Record != nil {
		d.Record(fmt.Sprintf(format, args...))
	}
}

func (d *DryRun) Query(ctx context.Context, name string, args ...string) (string, error) {
	return d.Base.Query(ctx, name, args...)
}

func (d *DryRun) ReadFile(path string) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if b, ok := d.files[path]; ok {
		return b, nil
	}
	if d.gone[path] {
		return nil, fs.ErrNotExist
	}
	return d.Base.ReadFile(path)
}

func (d *DryRun) Stat(path string) (fs.FileInfo, error) {
	d.mu.Lock()
	gone := d.gone[path]
	d.mu.Unlock()
	if gone {
		return nil, fs.ErrNotExist
	}
	return d.Base.Stat(path)
}

func (d *DryRun) Glob(pattern string) ([]string, error) { return d.Base.Glob(pattern) }
func (d *DryRun) LookPath(name string) (string, error)  { return d.Base.LookPath(name) }
func (d *DryRun) Getenv(key string) string              { return d.Base.Getenv(key) }

func (d *DryRun) Run(_ context.Context, c Cmd) (string, error) {
	d.note("$ %s", c.String())
	return "", nil
}

func (d *DryRun) WriteFile(path string, data []byte, perm fs.FileMode) error {
	old := ReadString(d, path)
	d.mu.Lock()
	d.files[path] = data
	delete(d.gone, path)
	d.mu.Unlock()
	if old == string(data) {
		return nil
	}
	d.note("write %s (mode %04o)\n%s", path, perm, Diff(path, old, string(data)))
	return nil
}

func (d *DryRun) Remove(path string) error {
	d.mu.Lock()
	delete(d.files, path)
	d.gone[path] = true
	d.mu.Unlock()
	d.note("remove %s", path)
	return nil
}

func (d *DryRun) RemoveAll(path string) error {
	d.note("remove -r %s", path)
	return nil
}

func (d *DryRun) MkdirAll(path string, perm fs.FileMode) error {
	if !Exists(d.Base, path) {
		d.note("mkdir -p -m %04o %s", perm, path)
	}
	return nil
}

func (d *DryRun) Chmod(path string, perm fs.FileMode) error {
	d.note("chmod %04o %s", perm, path)
	return nil
}

func (d *DryRun) Chown(path, user, group string) error {
	d.note("chown %s:%s %s", user, group, path)
	return nil
}

func (d *DryRun) Symlink(target, link string) error {
	d.note("ln -sfn %s %s", target, link)
	return nil
}

func (d *DryRun) CopyTree(src, dst string) error {
	d.note("cp -a %s %s", src, dst)
	return nil
}
