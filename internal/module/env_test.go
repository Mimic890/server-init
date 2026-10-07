package module_test

import (
	"context"
	"testing"
	"time"

	"github.com/mimic890/server-init/internal/config"
	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/state"
	"github.com/mimic890/server-init/internal/systest"
)

func newEnv(h *systest.Host) *module.Env {
	base := &module.Env{Answers: config.Default(), Sys: h, Run: state.NewRun(h, time.Unix(0, 0).UTC())}
	return base.For("test")
}

func TestPutFileBackupAndRollback(t *testing.T) {
	h := systest.New(t)
	h.Write("/etc/existing.conf", "original\n")
	env := newEnv(h)

	changed, err := env.PutFile("/etc/existing.conf", "managed\n", 0o644)
	if err != nil || !changed {
		t.Fatalf("PutFile: %v %v", changed, err)
	}
	if changed, _ := env.PutFile("/etc/existing.conf", "managed\n", 0o644); changed {
		t.Fatal("second PutFile with same content must be a no-op")
	}
	// a second change must keep the ORIGINAL backup
	if _, err := env.PutFile("/etc/existing.conf", "managed v2\n", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := env.PutFile("/etc/new.conf", "new\n", 0o600); err != nil {
		t.Fatal(err)
	}
	h.Write("/etc/old.conf", "old\n")
	if _, err := env.RemoveFile("/etc/old.conf"); err != nil {
		t.Fatal(err)
	}
	if err := env.Undo("test undo", "true", "undo-marker"); err != nil {
		t.Fatal(err)
	}

	if err := env.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.Read("/etc/existing.conf"); got != "original\n" {
		t.Fatalf("existing.conf = %q", got)
	}
	if h.Exists("/etc/new.conf") {
		t.Fatal("created file must be removed")
	}
	if got := h.Read("/etc/old.conf"); got != "old\n" {
		t.Fatalf("removed file must come back, got %q", got)
	}
	if !h.Ran("true undo-marker") {
		t.Fatal("undo command not run")
	}
	// journal archived: a second rollback has nothing to do
	es, _ := env.Journal.Entries()
	if len(es) != 0 {
		t.Fatalf("journal not archived: %v", es)
	}
}

func TestEditFileKeepsMode(t *testing.T) {
	h := systest.New(t)
	h.Write("/etc/fstab", "UUID=x / ext4 defaults 0 1\n")
	env := newEnv(h)
	if _, err := env.EditFile("/etc/fstab", 0o600, func(old string) string { return old + "/swapfile none swap sw 0 0\n" }); err != nil {
		t.Fatal(err)
	}
	st, _ := h.Stat("/etc/fstab")
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("mode changed to %o", st.Mode().Perm())
	}
}

func TestPlanFile(t *testing.T) {
	h := systest.New(t)
	h.Write("/etc/a.conf", "same\n")
	var p module.Plan
	if p.PlanFile(h, "/etc/a.conf", "same\n", 0o644, "a") {
		t.Fatal("unchanged file must not be planned")
	}
	if !p.PlanFile(h, "/etc/b.conf", "x\n", 0o644, "b") || p.Empty() || p.Changes[0].Diff == "" {
		t.Fatalf("plan: %+v", p)
	}
}

func TestAdvancedHidesInQuickMode(t *testing.T) {
	shown := false
	own := func() bool { return !shown }
	e := &module.Env{}
	if e.Advanced(nil)() || !e.Advanced(own)() {
		t.Fatal("normal mode: only the group's own condition hides it")
	}
	shown = true
	if e.Advanced(own)() {
		t.Fatal("normal mode: visible group hidden")
	}
	e.Quick = true
	if !e.Advanced(nil)() || !e.Advanced(own)() {
		t.Fatal("quick mode must hide advanced groups")
	}
}
