package cleanup

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/mimic890/server-init/internal/config"
	"github.com/mimic890/server-init/internal/facts"
	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/state"
	"github.com/mimic890/server-init/internal/systest"
)

func TestRenderGolden(t *testing.T) {
	systest.Golden(t, "journald.conf", RenderJournald("200M"))
	systest.Golden(t, "no-snapd.pref", RenderNoSnapd())
}

func TestDisableMotd(t *testing.T) {
	if got := DisableMotd("# x\nENABLED=1\nURLS=\"a\"\n"); got != "# x\nENABLED=0\nURLS=\"a\"\n" {
		t.Fatalf("got %q", got)
	}
}

func setup(t *testing.T) (*systest.Host, *module.Env) {
	h := systest.New(t)
	h.Write(MotdNews, "ENABLED=1\n")
	h.Write("/var/cache/apt/archives/x.deb", "deb")
	h.On("dpkg-query -W '-f=${Status}' snapd", "install ok installed")
	h.Fail("dpkg-query -W '-f=${Status}' cloud-init")
	h.On("dpkg-query -W '-f=${Status}' popularity-contest", "install ok installed")
	h.On("snap list", "Name Version Rev\ncore22 1 1\nlxd 5 1\n")
	h.On("apt-get -s", "0 upgraded, 0 newly installed, 2 to remove and 0 not upgraded.\n")
	a := config.Default()
	a.Cleanup.RemoveSnapd, a.Cleanup.RemoveCloudInit, a.Cleanup.RemovePopcon = true, true, true
	e := &module.Env{Answers: a, Facts: &facts.Facts{}, Sys: h,
		Run: state.NewRun(h, time.Unix(0, 0).UTC()), Log: slog.New(slog.DiscardHandler)}
	return h, e.For("cleanup")
}

func TestCheckAndApply(t *testing.T) {
	h, env := setup(t)
	m := New()
	p, err := m.Check(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	text := p.String()
	for _, want := range []string{"purge snapd", "purge popularity-contest", "core22, lxd", "MOTD news off",
		"disable motd-news.timer", "autoremove --purge (2 packages)", "apt clean (1 cached", "journal limited to 200M"} {
		if !strings.Contains(text, want) {
			t.Errorf("plan misses %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "cloud-init") {
		t.Error("cloud-init is not installed and must not be planned")
	}
	if err := m.Apply(context.Background(), env, p); err != nil {
		t.Fatal(err)
	}
	if !h.Ran("apt-get purge -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold snapd popularity-contest") {
		t.Fatalf("purge not run: %v", h.Cmds)
	}
	if h.Read(MotdNews) != "ENABLED=0\n" || h.Read(JournaldDropIn) != RenderJournald("200M") || !h.Exists(NoSnapdPin) {
		t.Fatal("files")
	}
	if err := m.Rollback(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if h.Read(MotdNews) != "ENABLED=1\n" || h.Exists(JournaldDropIn) {
		t.Fatal("rollback")
	}
}

func TestBadSize(t *testing.T) {
	_, env := setup(t)
	env.Answers.Cleanup.JournaldMaxUse = "lots"
	if _, err := New().Check(context.Background(), env); err == nil {
		t.Fatal("bad size accepted")
	}
}
