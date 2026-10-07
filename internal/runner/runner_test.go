package runner

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/mimic890/server-init/internal/config"
	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/module/moduletest"
	"github.com/mimic890/server-init/internal/state"
	"github.com/mimic890/server-init/internal/systest"
)

func env(h *systest.Host) *module.Env {
	return &module.Env{
		Answers: config.Default(),
		Sys:     h,
		Run:     state.NewRun(h, time.Unix(0, 0).UTC()),
		Log:     slog.New(slog.DiscardHandler),
	}
}

func TestApplyOrderAndStatus(t *testing.T) {
	h := systest.New(t)
	h.Write("/etc/ssh/sshd_config", "Port 22\n")
	a := &moduletest.Fake{IDValue: "a", Changes: moduletest.Change("/x")}
	b := &moduletest.Fake{IDValue: "b"} // nothing to do
	c := &moduletest.Fake{IDValue: "c", Changes: moduletest.Change("/y")}
	r := New(env(h), []module.Module{a, b, c})
	var events []Event
	r.Events = func(e Event) { events = append(events, e) }

	plans, err := r.Check(context.Background())
	if err != nil || len(plans) != 3 || !plans[1].Empty() {
		t.Fatalf("check: %v %+v", err, plans)
	}
	if err := r.Apply(context.Background(), plans); err != nil {
		t.Fatal(err)
	}
	if a.Applied != 1 || b.Applied != 0 || c.Applied != 1 {
		t.Fatalf("applied a=%d b=%d c=%d", a.Applied, b.Applied, c.Applied)
	}
	want := []Event{
		ModuleStarted{"a"}, ModuleFinished{ID: "a", Status: Done},
		ModuleStarted{"b"}, ModuleFinished{ID: "b", Status: Unchanged},
		ModuleStarted{"c"}, ModuleFinished{ID: "c", Status: Done},
	}
	if len(events) != len(want) {
		t.Fatalf("events = %+v", events)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("event %d = %+v, want %+v", i, events[i], want[i])
		}
	}
	if !h.Exists("/var/lib/server-init/backup-19700101-000000/snapshot/etc/ssh/sshd_config") {
		t.Fatal("snapshot of /etc/ssh missing")
	}
	if !h.Exists(state.Answers) {
		t.Fatal("answers not saved")
	}

	// second run: everything is already applied
	plans, _ = r.Check(context.Background())
	if !NothingToDo(plans) {
		t.Fatal("rerun must be a no-op")
	}
}

func TestApplyStopsOnFailure(t *testing.T) {
	h := systest.New(t)
	a := &moduletest.Fake{IDValue: "a", Changes: moduletest.Change("/x"), ApplyErr: errors.New("boom")}
	b := &moduletest.Fake{IDValue: "b", Changes: moduletest.Change("/y")}
	r := New(env(h), []module.Module{a, b})
	st := map[string]Status{}
	r.Events = func(e Event) {
		if f, ok := e.(ModuleFinished); ok {
			st[f.ID] = f.Status
		}
	}
	plans, _ := r.Check(context.Background())
	if err := r.Apply(context.Background(), plans); err == nil {
		t.Fatal("expected error")
	}
	if st["a"] != Failed || st["b"] != NotRun || b.Applied != 0 {
		t.Fatalf("status = %v, b applied %d", st, b.Applied)
	}
	if h.Exists(state.Answers) {
		t.Fatal("answers must not be saved after a failure")
	}
}

func TestNothingToDoSkipsBackup(t *testing.T) {
	h := systest.New(t)
	a := &moduletest.Fake{IDValue: "a"}
	r := New(env(h), []module.Module{a})
	plans, _ := r.Check(context.Background())
	if err := r.Apply(context.Background(), plans); err != nil {
		t.Fatal(err)
	}
	if h.Exists(state.StateDir) {
		t.Fatal("no backup must be created when nothing changes")
	}
}

func TestRollbackReverseOrder(t *testing.T) {
	h := systest.New(t)
	a := &moduletest.Fake{IDValue: "a"}
	b := &moduletest.Fake{IDValue: "b"}
	r := New(env(h), []module.Module{a, b})
	if err := r.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.Rolled != 1 || b.Rolled != 1 {
		t.Fatal("rollback not called")
	}
}

func TestRestoreLatestBackup(t *testing.T) {
	h := systest.New(t)
	h.Write("/etc/ssh/sshd_config", "Port 22\n")
	e := env(h)
	if err := e.Run.Snapshot(); err != nil {
		t.Fatal(err)
	}
	h.Write("/etc/ssh/sshd_config", "Port 2222\n")
	h.Write("/etc/ssh/sshd_config.d/00-server-init.conf", "x\n")
	if err := RestoreLatestBackup(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if h.Read("/etc/ssh/sshd_config") != "Port 22\n" || h.Exists("/etc/ssh/sshd_config.d/00-server-init.conf") {
		t.Fatal("snapshot not restored exactly")
	}
	if !h.Ran("systemctl restart ssh.service") {
		t.Fatal("ssh not restarted")
	}
}
