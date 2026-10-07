package preflight

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mimic890/server-init/internal/config"
	"github.com/mimic890/server-init/internal/facts"
	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/state"
	"github.com/mimic890/server-init/internal/systest"
)

func env(t *testing.T, f *facts.Facts) (*module.Env, *systest.Host) {
	h := systest.New(t)
	for _, tool := range []string{"ss", "systemctl", "dpkg-query", "apt-get"} {
		h.Tools[tool] = true
	}
	e := &module.Env{Answers: config.Default(), Facts: f, Sys: h, Run: state.NewRun(h, time.Unix(0, 0).UTC())}
	return e.For("preflight"), h
}

func good() *facts.Facts {
	return &facts.Facts{IsRoot: true, Systemd: true, OSSupported: true, Internet: true, FreeDiskMB: 5000, OSPretty: "Debian GNU/Linux 12"}
}

func TestCheckOK(t *testing.T) {
	e, _ := env(t, good())
	p, err := New().Check(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Empty() || len(p.Notes) != 0 {
		t.Fatalf("preflight plan must only hold info: %+v", p)
	}
}

func TestCheckBlocking(t *testing.T) {
	f := good()
	f.IsRoot, f.Systemd, f.FreeDiskMB = false, false, 100
	e, _ := env(t, f)
	_, err := New().Check(context.Background(), e)
	if err == nil {
		t.Fatal("expected blocking error")
	}
	for _, want := range []string{"root", "systemd", "MB free"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q misses %q", err, want)
		}
	}
}

func TestCheckWarnings(t *testing.T) {
	f := good()
	f.OSSupported, f.Internet = false, false
	e, h := env(t, f)
	h.Write(LegacyDropIn, "Port 2222\n")
	p, err := New().Check(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Notes) != 3 {
		t.Fatalf("notes = %q", p.Notes)
	}
}

func TestMissingTool(t *testing.T) {
	e, h := env(t, good())
	delete(h.Tools, "ss")
	if _, err := New().Check(context.Background(), e); err == nil || !strings.Contains(err.Error(), "ss not found") {
		t.Fatalf("err = %v", err)
	}
}
