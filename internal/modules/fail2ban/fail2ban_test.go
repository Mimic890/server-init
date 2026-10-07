package fail2ban

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

func init() { pollInterval = time.Millisecond }

func TestRenderGolden(t *testing.T) {
	systest.Golden(t, "jail-recidive.local", RenderJail(JailParams{Ports: []int{40022}, MaxRetry: 3, FindTime: "10m", BanTime: "1h", Recidive: true}))
	systest.Golden(t, "jail-norecidive.local", RenderJail(JailParams{Ports: []int{22, 40022}, MaxRetry: 5, FindTime: "1h", BanTime: "-1"}))
	systest.Golden(t, "whitelist.local", RenderWhitelist([]string{"203.0.113.7", "10.0.0.0/8"}))
	systest.Golden(t, "blacklist-filter.conf", RenderFilter())
}

func setup(t *testing.T) (*systest.Host, *module.Env) {
	h := systest.New(t)
	h.Tools["fail2ban-client"] = true
	h.Tools["nft"] = true
	h.On("dpkg-query -W '-f=${Status}' fail2ban", "install ok installed")
	h.On("dpkg-query -W '-f=${Status}' python3-systemd", "install ok installed")
	a := config.Default()
	a.SSH.Port = 40022
	e := &module.Env{
		Answers:  a,
		Facts:    &facts.Facts{IsRoot: true, SSHPorts: []int{22}, ClientIP: "203.0.113.7"},
		Sys:      h,
		Run:      state.NewRun(h, time.Unix(0, 0).UTC()),
		Log:      slog.New(slog.DiscardHandler),
		Selected: func(id string) bool { return id == "ssh" },
	}
	return h, e.For("fail2ban")
}

func TestApplyAndRerun(t *testing.T) {
	h, env := setup(t)
	h.Write(WhitelistList, "198.51.100.1\n") // manual addition from an earlier run
	h.Fail("systemctl is-enabled --quiet fail2ban")
	m := New()
	p, err := m.Check(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.String(), "port = 40022") {
		t.Fatalf("jail must use the new SSH port:\n%s", p.String())
	}
	if err := m.Apply(context.Background(), env, p); err != nil {
		t.Fatal(err)
	}
	if got := h.Read(WhitelistList); got != "198.51.100.1\n203.0.113.7\n" {
		t.Fatalf("whitelist = %q (manual entries must be kept)", got)
	}
	if !strings.Contains(h.Read(WhitelistJail), "ignoreip = 127.0.0.1/8 ::1 198.51.100.1 203.0.113.7") {
		t.Fatal(h.Read(WhitelistJail))
	}
	if !h.Ran("fail2ban-client -t") || !h.Ran("systemctl restart fail2ban") {
		t.Fatal("not validated / restarted")
	}
	delete(h.Responses, "systemctl is-enabled --quiet fail2ban")
	p, _ = m.Check(context.Background(), env)
	if !p.Empty() {
		t.Fatalf("rerun must be a no-op:\n%s", p.String())
	}
}

func TestInvalidConfigStops(t *testing.T) {
	h, env := setup(t)
	h.Fail("fail2ban-client -t")
	err := New().Apply(context.Background(), env, module.Plan{})
	if err == nil || h.Ran("systemctl restart fail2ban") {
		t.Fatalf("must stop before restarting: %v", err)
	}
}

func TestValidation(t *testing.T) {
	_, env := setup(t)
	env.Answers.Fail2ban.BanTime = "forever"
	if _, err := New().Check(context.Background(), env); err == nil {
		t.Fatal("bad bantime accepted")
	}
	env.Answers.Fail2ban.BanTime = "-1"
	env.Answers.Fail2ban.Whitelist = []string{"nope"}
	if _, err := New().Check(context.Background(), env); err == nil {
		t.Fatal("bad whitelist accepted")
	}
}

func TestLegacyMigration(t *testing.T) {
	h, env := setup(t)
	h.Write("/etc/fail2ban/jail.d/ssh-setup.local", "[sshd]\n")
	h.Write("/etc/ssh-setup/blacklist.list", "192.0.2.66\n")
	m := New()
	if err := m.Apply(context.Background(), env, module.Plan{}); err != nil {
		t.Fatal(err)
	}
	if h.Exists("/etc/fail2ban/jail.d/ssh-setup.local") {
		t.Fatal("legacy jail not removed")
	}
	if h.Read(BlacklistList) != "192.0.2.66\n" || !h.Ran("fail2ban-client set server-init-blacklist banip 192.0.2.66") {
		t.Fatal("legacy blacklist not taken over")
	}
}

func TestCLI(t *testing.T) {
	h, env := setup(t)
	var out strings.Builder
	run := func(args ...string) error { out.Reset(); return Command(context.Background(), env, args, &out) }
	if err := run("whitelist", "add", "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	if h.Read(WhitelistList) != "203.0.113.9\n" || !strings.Contains(h.Read(WhitelistJail), "203.0.113.9") {
		t.Fatal("whitelist add")
	}
	if !h.Ran("fail2ban-client unban 203.0.113.9") {
		t.Fatal("whitelisted IP must be unbanned")
	}
	if err := run("blacklist", "add", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if !h.Ran("fail2ban-client set server-init-blacklist banip 192.0.2.1") {
		t.Fatal("not banned")
	}
	if err := run("blacklist", "list"); err != nil || out.String() != "192.0.2.1\n" {
		t.Fatalf("list = %q %v", out.String(), err)
	}
	if err := run("whitelist", "del", "203.0.113.9"); err != nil || h.Read(WhitelistList) != "" {
		t.Fatal("whitelist del")
	}
	if err := run("unban", "not-an-ip"); err == nil {
		t.Fatal("invalid IP accepted")
	}
	if err := run("bogus"); err == nil {
		t.Fatal("unknown command accepted")
	}
}
