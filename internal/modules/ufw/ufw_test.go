package ufw

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mimic890/server-init/internal/config"
	"github.com/mimic890/server-init/internal/facts"
	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/state"
	"github.com/mimic890/server-init/internal/systest"
)

func TestDockerBlockGolden(t *testing.T) {
	systest.Golden(t, "docker-after.rules", DockerBlock(false))
	systest.Golden(t, "docker-after6.rules", DockerBlock(true))
}

func TestRuleArgs(t *testing.T) {
	r := limitRule(40022, "SSH")
	if got := strings.Join(r.Args(), "|"); got != "limit|40022/tcp|comment|SSH server-init" {
		t.Fatalf("args = %s", got)
	}
	if got := strings.Join(r.DeleteArgs(), " "); got != "delete limit 40022/tcp" {
		t.Fatalf("delete = %s", got)
	}
	added := "Added user rules (see 'ufw status' for running firewall):\nufw limit 40022/tcp comment 'SSH server-init'\nufw allow 22/tcp\n"
	if rules := ParseAdded(added); len(rules) != 2 || rules[0] != r {
		t.Fatalf("parse = %q", rules)
	}
}

func TestWithDockerBlockIdempotent(t *testing.T) {
	base := "*filter\n:ufw-after-input - [0:0]\nCOMMIT\n"
	once := WithDockerBlock(base, false)
	if !strings.HasPrefix(once, base) || !HasDockerBlock(once) || WithDockerBlock(once, false) != once {
		t.Fatalf("not idempotent:\n%s", once)
	}
}

// fakeUFW simulates the ufw command.
type fakeUFW struct {
	mu        sync.Mutex
	active    bool
	rules     []Rule
	dropLimit bool // ufw "forgets" the SSH rule
}

func (f *fakeUFW) hook(line string) (string, error, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case line == "ufw status":
		if f.active {
			return "Status: active\n", nil, true
		}
		return "Status: inactive\n", nil, true
	case line == "ufw show added":
		out := "Added user rules (see 'ufw status' for running firewall):\n"
		for _, r := range f.rules {
			out += "ufw " + string(r) + "\n"
		}
		return out, nil, true
	case line == "ufw --force enable":
		f.active = true
		return "", nil, true
	case strings.HasPrefix(line, "ufw delete "):
		rest := strings.TrimPrefix(line, "ufw delete ")
		f.rules = slices.DeleteFunc(f.rules, func(r Rule) bool { return strings.HasPrefix(string(r), rest) })
		return "", nil, true
	case strings.HasPrefix(line, "ufw limit "), strings.HasPrefix(line, "ufw allow "):
		r := strings.TrimPrefix(line, "ufw ")
		if f.dropLimit && strings.HasPrefix(r, "limit") {
			return "", nil, true
		}
		f.rules = append(f.rules, Rule(r))
		return "", nil, true
	}
	return "", nil, false
}

func setup(t *testing.T) (*systest.Host, *fakeUFW, *module.Env) {
	h := systest.New(t)
	f := &fakeUFW{}
	h.Hook = f.hook
	h.Tools["ufw"] = true
	h.Fail("systemctl is-active --quiet firewalld")
	h.Write(DefaultFile, "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n")
	h.Write(AfterRules, "*filter\nCOMMIT\n")
	a := config.Default()
	a.SSH.Port = 40022
	a.UFW.AllowHTTPS = true
	e := &module.Env{
		Answers:  a,
		Facts:    &facts.Facts{SSHPorts: []int{22}},
		Sys:      h,
		Run:      state.NewRun(h, time.Unix(0, 0).UTC()),
		Log:      slog.New(slog.DiscardHandler),
		Selected: func(id string) bool { return id == "ssh" },
	}
	return h, f, e.For("ufw")
}

// shellArgs turns "comment 'SSH server-init'" (quoted by sys.Cmd) back into
// the stored rule form.
func normalize(f *fakeUFW) {
	for i, r := range f.rules {
		f.rules[i] = Rule(strings.ReplaceAll(string(r), `'\''`, `'`))
	}
}

func TestApplyEnablesWithSSHRule(t *testing.T) {
	h, f, env := setup(t)
	m := New()
	p, err := m.Check(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	text := p.String()
	for _, want := range []string{"ufw limit 40022/tcp comment 'SSH server-init'", "ufw allow 443/tcp", "DOCKER-USER", "enable ufw"} {
		if !strings.Contains(text, want) {
			t.Errorf("plan misses %q:\n%s", want, text)
		}
	}
	if err := m.Apply(context.Background(), env, p); err != nil {
		t.Fatal(err)
	}
	normalize(f)
	if !f.active {
		t.Fatal("ufw not enabled")
	}
	if !HasDockerBlock(h.Read(AfterRules)) {
		t.Fatal("docker block missing")
	}
	// enable must come after the SSH rule
	iLimit, iEnable := -1, -1
	for i, c := range h.Cmds {
		if strings.HasPrefix(c, "ufw limit 40022/tcp") && iLimit < 0 {
			iLimit = i
		}
		if c == "ufw --force enable" {
			iEnable = i
		}
	}
	if iLimit < 0 || iEnable < iLimit {
		t.Fatalf("enable before the SSH rule: %v", h.Cmds)
	}
	p, _ = m.Check(context.Background(), env)
	if !p.Empty() {
		t.Fatalf("rerun must be a no-op:\n%s", p.String())
	}
}

func TestNeverEnableWithoutSSHRule(t *testing.T) {
	_, f, env := setup(t)
	f.dropLimit = true
	m := New()
	p, _ := m.Check(context.Background(), env)
	err := m.Apply(context.Background(), env, p)
	if err == nil || !strings.Contains(err.Error(), "NOT enabled") || f.active {
		t.Fatalf("err = %v, active = %v", err, f.active)
	}
}

func TestFirewalldSkips(t *testing.T) {
	h, f, env := setup(t)
	h.On("systemctl is-active --quiet firewalld", "")
	m := New()
	p, err := m.Check(context.Background(), env)
	if err != nil || !p.Empty() || len(p.Notes) == 0 || !strings.Contains(p.Notes[0], "firewalld") {
		t.Fatalf("plan: %v %+v", err, p)
	}
	if err := m.Apply(context.Background(), env, p); err != nil || f.active {
		t.Fatal("must not touch ufw")
	}
}

func TestCustomDropPolicySkips(t *testing.T) {
	h, _, env := setup(t)
	h.Fail("systemctl is-active --quiet firewalld")
	h.Tools["iptables"] = true
	h.On("iptables -S INPUT", "-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\n")
	p, _ := New().Check(context.Background(), env)
	if len(p.Notes) == 0 || !strings.Contains(p.Notes[0], "iptables") {
		t.Fatalf("notes = %q", p.Notes)
	}
}

func TestStaleSSHRulesRemoved(t *testing.T) {
	_, f, env := setup(t)
	h := env.Sys.(*systest.Host)
	h.Fail("systemctl is-active --quiet firewalld")
	f.active = true
	f.rules = []Rule{"limit 22/tcp comment 'SSH server-init'", "allow 22/tcp"}
	m := New()
	p, _ := m.Check(context.Background(), env)
	if !strings.Contains(p.String(), "remove old rule: ufw limit 22/tcp") {
		t.Fatalf("plan:\n%s", p.String())
	}
	if len(p.Notes) == 0 || !strings.Contains(strings.Join(p.Notes, "\n"), "ufw delete allow 22/tcp") {
		t.Fatalf("foreign old rule must only be reported: %q", p.Notes)
	}
	if err := m.Apply(context.Background(), env, p); err != nil {
		t.Fatal(err)
	}
	normalize(f)
	if slices.Contains(f.rules, Rule("limit 22/tcp comment 'SSH server-init'")) || !slices.Contains(f.rules, Rule("allow 22/tcp")) {
		t.Fatalf("rules = %q", f.rules)
	}
}

func TestRollbackDisables(t *testing.T) {
	h, f, env := setup(t)
	m := New()
	p, _ := m.Check(context.Background(), env)
	if err := m.Apply(context.Background(), env, p); err != nil {
		t.Fatal(err)
	}
	if err := m.Rollback(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if !h.Ran("ufw --force disable") || HasDockerBlock(h.Read(AfterRules)) {
		t.Fatal("rollback incomplete")
	}
	_ = f
}
