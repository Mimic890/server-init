// Package state keeps what server-init changed: per-run backups and a
// per-module journal that Rollback replays in reverse.
package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mimic890/server-init/internal/sys"
)

// Well-known locations.
const (
	ConfDir    = "/etc/server-init"
	StateDir   = "/var/lib/server-init"
	JournalDir = StateDir + "/state"
	LastBackup = StateDir + "/last-backup"
	Answers    = ConfDir + "/answers.yaml"
)

// SnapshotDirs are copied as a whole before every apply; the global
// --rollback restores them.
var SnapshotDirs = []string{"/etc/ssh", "/etc/ufw", "/etc/fail2ban", "/etc/sudoers.d", "/etc/sysctl.d"}

// Op is a journal operation.
type Op string

const (
	OpCreate  Op = "create"  // file did not exist -> rollback deletes it
	OpModify  Op = "modify"  // file existed -> rollback restores Backup
	OpRemove  Op = "remove"  // file was deleted -> rollback restores Backup
	OpPackage Op = "package" // packages installed (kept on rollback, only reported)
	OpUndo    Op = "undo"    // command to run on rollback
)

// Entry is one journal record.
type Entry struct {
	Op       Op        `json:"op"`
	Path     string    `json:"path,omitempty"`
	Backup   string    `json:"backup,omitempty"`
	Packages []string  `json:"packages,omitempty"`
	Undo     []string  `json:"undo,omitempty"`
	Note     string    `json:"note,omitempty"`
	Time     time.Time `json:"time"`
}

// Run is one apply run with its backup directory.
type Run struct {
	S    sys.System
	Dir  string // /var/lib/server-init/backup-<ts>
	once sync.Once
	err  error
}

// NewRun prepares (but does not create) a backup directory for this run.
func NewRun(s sys.System, now time.Time) *Run {
	return &Run{S: s, Dir: filepath.Join(StateDir, "backup-"+now.Format("20060102-150405"))}
}

func (r *Run) ensure() error {
	r.once.Do(func() {
		for _, d := range []string{StateDir, JournalDir, r.Dir} {
			if err := r.S.MkdirAll(d, 0o700); err != nil {
				r.err = err
				return
			}
		}
		r.err = r.S.Symlink(r.Dir, LastBackup)
	})
	return r.err
}

// Snapshot copies the SnapshotDirs into the run directory.
func (r *Run) Snapshot() error {
	if err := r.ensure(); err != nil {
		return err
	}
	for _, d := range SnapshotDirs {
		if !sys.Exists(r.S, d) {
			continue
		}
		if err := r.S.CopyTree(d, filepath.Join(r.Dir, "snapshot", d)); err != nil {
			return fmt.Errorf("backup %s: %w", d, err)
		}
	}
	return nil
}

// BackupFile copies one file into the run directory and returns the copy's
// path.
func (r *Run) BackupFile(path string) (string, error) {
	if err := r.ensure(); err != nil {
		return "", err
	}
	dst := filepath.Join(r.Dir, "files", path)
	if err := r.S.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}
	if err := r.S.CopyTree(path, dst); err != nil {
		return "", err
	}
	return dst, nil
}

// Journal is the list of changes one module made, across all runs.
type Journal struct {
	S      sys.System
	Module string
	mu     sync.Mutex
}

// NewJournal returns the journal of a module.
func NewJournal(s sys.System, module string) *Journal {
	return &Journal{S: s, Module: module}
}

func (j *Journal) path() string { return filepath.Join(JournalDir, j.Module+".json") }

// Entries returns all recorded entries, oldest first.
func (j *Journal) Entries() ([]Entry, error) {
	b, err := j.S.ReadFile(j.path())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var es []Entry
	if err := json.Unmarshal(b, &es); err != nil {
		return nil, fmt.Errorf("journal %s: %w", j.path(), err)
	}
	return es, nil
}

// Knows reports whether path already has a create/modify/remove record, in
// which case the original state is already preserved.
func (j *Journal) Knows(path string) bool {
	es, _ := j.Entries()
	for _, e := range es {
		if e.Path == path && (e.Op == OpCreate || e.Op == OpModify || e.Op == OpRemove) {
			return true
		}
	}
	return false
}

// Add appends an entry. In dry-run mode nothing is stored.
func (j *Journal) Add(e Entry) error {
	if j.S.DryRun() {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	es, err := j.Entries()
	if err != nil {
		return err
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	es = append(es, e)
	b, err := json.MarshalIndent(es, "", "  ")
	if err != nil {
		return err
	}
	if err := j.S.MkdirAll(JournalDir, 0o700); err != nil {
		return err
	}
	return j.S.WriteFile(j.path(), append(b, '\n'), 0o600)
}

// Replay undoes all entries in reverse order and archives the journal.
// logf receives one line per step.
func (j *Journal) Replay(ctx context.Context, logf func(format string, args ...any)) error {
	es, err := j.Entries()
	if err != nil {
		return err
	}
	if len(es) == 0 {
		logf("%s: nothing to roll back", j.Module)
		return nil
	}
	var errs []error
	done := map[string]bool{}
	for _, e := range slices.Backward(es) {
		switch e.Op {
		case OpCreate:
			if done[e.Path] {
				continue
			}
			done[e.Path] = true
			if err := j.S.Remove(e.Path); err != nil {
				errs = append(errs, err)
			}
			logf("removed %s", e.Path)
		case OpModify, OpRemove:
			if done[e.Path] {
				continue
			}
			done[e.Path] = true
			if err := j.S.CopyTree(e.Backup, e.Path); err != nil {
				errs = append(errs, err)
			}
			logf("restored %s", e.Path)
		case OpUndo:
			if len(e.Undo) == 0 {
				continue
			}
			if _, err := j.S.Run(ctx, sys.Command(e.Undo[0], e.Undo[1:]...)); err != nil {
				errs = append(errs, err)
			}
			logf("ran %s", strings.Join(e.Undo, " "))
		case OpPackage:
			logf("kept installed packages: %s", strings.Join(e.Packages, " "))
		}
	}
	if !j.S.DryRun() {
		b, _ := j.S.ReadFile(j.path())
		archived := j.path() + ".rolled-back-" + time.Now().Format("20060102-150405")
		if err := j.S.WriteFile(archived, b, 0o600); err == nil {
			_ = j.S.Remove(j.path())
		}
	}
	return errors.Join(errs...)
}

// LatestRunDir returns the newest backup-<ts> directory, or "".
func LatestRunDir(s sys.System) string {
	m, _ := s.Glob(filepath.Join(StateDir, "backup-*"))
	sort.Strings(m)
	if len(m) == 0 {
		return ""
	}
	return m[len(m)-1]
}

// RestoreSnapshot puts the SnapshotDirs of runDir back in place. Directories
// that did not exist at snapshot time are left alone.
func RestoreSnapshot(s sys.System, runDir string, logf func(format string, args ...any)) error {
	var errs []error
	for _, d := range SnapshotDirs {
		src := filepath.Join(runDir, "snapshot", d)
		if !sys.Exists(s, src) {
			continue
		}
		if err := s.RemoveAll(d); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := s.CopyTree(src, d); err != nil {
			errs = append(errs, err)
			continue
		}
		logf("restored %s from %s", d, runDir)
	}
	return errors.Join(errs...)
}
