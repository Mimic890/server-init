package ssh

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"log/slog"
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

func init() { pollInterval = time.Millisecond }

func testKey() string {
	pub, _, _ := ed25519.GenerateKey(nil)
	var b []byte
	for _, p := range [][]byte{[]byte("ssh-ed25519"), pub} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(p)))
		b = append(b, p...)
	}
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(b) + " me@pc"
}

type fakePrompt struct {
	interactive bool
	answer      bool
	err         error
	got         module.LoginCheck
	asked       int
}

func (f *fakePrompt) Interactive() bool { return f.interactive }
func (f *fakePrompt) ConfirmLogin(_ context.Context, c module.LoginCheck) (bool, error) {
	f.got = c
	f.asked++
	return f.answer, f.err
}
func (f *fakePrompt) Confirm(context.Context, string, bool) (bool, error) { return true, nil }

// server simulates sshd: ports start listening after a restart, according
// to the drop-in.
type server struct {
	*systest.Host
	mu        sync.Mutex
	listening map[string]bool
	sshdTFail bool
}

func newServer(t *testing.T) *server {
	s := &server{Host: systest.New(t), listening: map[string]bool{"22": true}}
	for _, tool := range []string{"sshd", "ss", "systemctl"} {
		s.Tools[tool] = true
	}
	s.Write("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nPasswordAuthentication yes\n")
	s.Write(HostKey, "key")
	s.On("getent passwd root", "root:x:0:0:root:/root:/bin/bash\n")
	s.On("id -gn root", "root\n")
	s.On("sshd -T -C", "port 22\npasswordauthentication no\nkbdinteractiveauthentication no\n")
	s.Hook = func(line string) (string, error, bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case strings.HasPrefix(line, "ss -H -ltn 'sport = :"):
			port := strings.TrimSuffix(strings.TrimPrefix(line, "ss -H -ltn 'sport = :"), "'")
			if s.listening[port] {
				return "LISTEN 0 128 0.0.0.0:" + port + " 0.0.0.0:*\n", nil, true
			}
			return "", nil, true
		case line == "sshd -t":
			if s.sshdTFail {
				return "bad config", errors.New("exit status 255"), true
			}
			return "", nil, true
		case strings.HasPrefix(line, "systemctl restart ssh"):
			s.listening = map[string]bool{}
			for _, l := range strings.Split(s.Read(DropIn), "\n") {
				if p, ok := strings.CutPrefix(l, "Port "); ok {
					s.listening[p] = true
				}
			}
			return "", nil, true
		}
		return "", nil, false
	}
	return s
}

func newEnv(s *server, p module.Prompter) *module.Env {
	a := config.Default()
	a.SSH.Port = 40022
	a.SSH.User = "root"
	a.SSH.PublicKey = testKey()
	e := &module.Env{
		Answers: a,
		Facts:   &facts.Facts{IsRoot: true, Systemd: true, SSHPorts: []int{22}, ServerIP: "203.0.113.1", Hostname: "srv"},
		Sys:     s,
		Run:     state.NewRun(s, time.Unix(0, 0).UTC()),
		Prompt:  p,
		Log:     slog.New(slog.DiscardHandler),
	}
	return e.For("ssh")
}

func TestCheckPlan(t *testing.T) {
	s := newServer(t)
	env := newEnv(s, &fakePrompt{})
	p, err := New().Check(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	text := p.String()
	for _, want := range []string{"Port 22 -> 40022", "comment out the active Port line in /etc/ssh/sshd_config",
		"add the public key to /root/.ssh/authorized_keys", "+PasswordAuthentication no"} {
		if !strings.Contains(text, want) {
			t.Errorf("plan misses %q:\n%s", want, text)
		}
	}
	if len(s.Cmds) == 0 || s.Ran("systemctl restart") || s.Exists(DropIn) {
		t.Fatal("Check must not change anything")
	}
}

func TestCheckRejectsBadAnswers(t *testing.T) {
	s := newServer(t)
	env := newEnv(s, &fakePrompt{})
	env.Answers.SSH.PublicKey = "ssh-rsa AAAA"
	if _, err := New().Check(context.Background(), env); err == nil || !strings.Contains(err.Error(), "ed25519") {
		t.Fatalf("err = %v", err)
	}
	env.Answers.SSH.PublicKey = testKey()
	s.listening["40022"] = true // used by another program
	if _, err := New().Check(context.Background(), env); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("err = %v", err)
	}
}

func TestApplyConfirmed(t *testing.T) {
	s := newServer(t)
	pr := &fakePrompt{interactive: true, answer: true}
	env := newEnv(s, pr)
	m := New()
	if err := m.Apply(context.Background(), env, module.Plan{}); err != nil {
		t.Fatal(err)
	}
	if pr.asked != 1 || pr.got.Command != "ssh -p 40022 root@203.0.113.1" {
		t.Fatalf("login check: %+v", pr.got)
	}
	cfg := s.Read(DropIn)
	if !strings.Contains(cfg, "Port 40022\n") || strings.Contains(cfg, "Port 22\n") {
		t.Fatalf("final config must only have the new port:\n%s", cfg)
	}
	if !strings.Contains(s.Read("/etc/ssh/sshd_config"), "# disabled by server-init: Port 22") {
		t.Fatal("old Port line not neutralized")
	}
	if !strings.Contains(s.Read("/root/.ssh/authorized_keys"), env.Answers.SSH.PublicKey) {
		t.Fatal("key not installed")
	}
	if !s.Ran("systemd-run --quiet --unit=server-init-ssh-watchdog --on-active=180s --timer-property=AccuracySec=1s /bin/bash " + RollbackScript) {
		t.Fatalf("watchdog not armed: %v", s.Cmds)
	}
	if s.Ran("bash " + RollbackScript) {
		t.Fatal("rollback must not run after confirmation")
	}
	if s.Count("systemctl restart ssh.service") != 2 {
		t.Fatal("expected two restarts (phase 1 and final)")
	}
	script := s.Read(RollbackScript)
	if !strings.Contains(script, "rm -f '"+DropIn+"'") || !strings.Contains(script, "files/etc/ssh/sshd_config' '/etc/ssh/sshd_config'") {
		t.Fatalf("rollback script:\n%s", script)
	}
	if len(m.Report(env)) == 0 {
		t.Fatal("empty report")
	}

	// Rerun: the host now listens on 40022 only -> nothing to do.
	env.Facts.SSHPorts = []int{40022}
	p, err := m.Check(context.Background(), env)
	if err != nil || !p.Empty() {
		t.Fatalf("rerun must be a no-op: %v\n%s", err, p.String())
	}
}

func TestApplyNotConfirmedRollsBack(t *testing.T) {
	s := newServer(t)
	env := newEnv(s, &fakePrompt{interactive: true, answer: false})
	err := New().Apply(context.Background(), env, module.Plan{})
	if err == nil || !strings.Contains(err.Error(), "not confirmed") {
		t.Fatalf("err = %v", err)
	}
	if !s.Ran("bash " + RollbackScript) {
		t.Fatal("rollback script not run")
	}
	if !s.Ran("systemctl stop server-init-ssh-watchdog.timer") {
		t.Fatal("watchdog not stopped")
	}
}

func TestApplySshdTestFails(t *testing.T) {
	s := newServer(t)
	s.sshdTFail = true
	pr := &fakePrompt{interactive: true, answer: true}
	err := New().Apply(context.Background(), newEnv(s, pr), module.Plan{})
	if err == nil || !strings.Contains(err.Error(), "sshd rejected") {
		t.Fatalf("err = %v", err)
	}
	if s.Ran("systemctl restart") || pr.asked != 0 {
		t.Fatal("must stop before restarting sshd")
	}
}

func TestApplyPasswordStillOn(t *testing.T) {
	s := newServer(t)
	s.On("sshd -T -C", "passwordauthentication yes\nkbdinteractiveauthentication no\n")
	err := New().Apply(context.Background(), newEnv(s, &fakePrompt{interactive: true, answer: true}), module.Plan{})
	if err == nil || !strings.Contains(err.Error(), "password authentication") {
		t.Fatalf("err = %v", err)
	}
}

func TestApplyNonInteractivePastedKeyKeepsOldPort(t *testing.T) {
	s := newServer(t)
	m := New()
	env := newEnv(s, module.AutoPrompter{})
	if err := m.Apply(context.Background(), env, module.Plan{}); err != nil {
		t.Fatal(err)
	}
	cfg := s.Read(DropIn)
	if !strings.Contains(cfg, "Port 22\n") || !strings.Contains(cfg, "Port 40022\n") {
		t.Fatalf("both ports must stay open:\n%s", cfg)
	}
	if !s.Exists(PendingFile) || !m.res.pending {
		t.Fatal("pending finalize not recorded")
	}
	if s.Ran("bash " + RollbackScript) {
		t.Fatal("must not roll back")
	}

	// server-init ssh finalize
	var out strings.Builder
	if err := Command(context.Background(), env, []string{"finalize"}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s.Read(DropIn), "Port 22\n") || s.Exists(PendingFile) {
		t.Fatal("finalize did not close the old port")
	}
}

func TestApplyNonInteractiveGeneratedKeyIsVerified(t *testing.T) {
	s := newServer(t)
	env := newEnv(s, module.AutoPrompter{})
	env.Answers.SSH.KeyMode = "generate"
	s.Hook = chain(s.Hook, func(line string) (string, error, bool) {
		if strings.HasPrefix(line, "ssh-keygen -q -t ed25519 -a 100") {
			s.Write("/root/.ssh/server-init_ed25519", "PRIVATE")
			s.Write("/root/.ssh/server-init_ed25519.pub", testKey())
			return "", nil, true
		}
		return "", nil, false
	})
	m := New()
	if err := m.Apply(context.Background(), env, module.Plan{}); err != nil {
		t.Fatal(err)
	}
	if !s.Ran("ssh -o BatchMode=yes") {
		t.Fatal("automatic login test not run")
	}
	if strings.Contains(s.Read(DropIn), "Port 22\n") || m.res.pending {
		t.Fatal("verified login must close the old port")
	}
	if !s.Exists("/root/.ssh/server-init_ed25519") {
		t.Fatal("non-interactive run must keep the private key")
	}
}

func TestSocketActivation(t *testing.T) {
	s := newServer(t)
	env := newEnv(s, &fakePrompt{interactive: true, answer: true})
	env.Facts.SSHSocket = true
	if err := New().Apply(context.Background(), env, module.Plan{}); err != nil {
		t.Fatal(err)
	}
	if got := s.Read(SocketDropIn); got != RenderSocket([]int{40022}) {
		t.Fatalf("socket drop-in:\n%s", got)
	}
	if !s.Ran("systemctl restart ssh.socket") {
		t.Fatal("socket not restarted")
	}
}

func TestLegacyMigration(t *testing.T) {
	s := newServer(t)
	s.Write("/etc/ssh/sshd_config.d/00-ssh-setup.conf", "Port 22\n")
	env := newEnv(s, &fakePrompt{interactive: true, answer: true})
	p, err := New().Check(context.Background(), env)
	if err != nil || !p.Has("/etc/ssh/sshd_config.d/00-ssh-setup.conf") {
		t.Fatalf("migration not planned: %v %s", err, p.String())
	}
	if err := New().Apply(context.Background(), env, module.Plan{}); err != nil {
		t.Fatal(err)
	}
	if s.Exists("/etc/ssh/sshd_config.d/00-ssh-setup.conf") {
		t.Fatal("legacy drop-in not removed")
	}
}

func TestModuleRollback(t *testing.T) {
	s := newServer(t)
	orig := s.Read("/etc/ssh/sshd_config")
	env := newEnv(s, &fakePrompt{interactive: true, answer: true})
	m := New()
	if err := m.Apply(context.Background(), env, module.Plan{}); err != nil {
		t.Fatal(err)
	}
	if err := m.Rollback(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if s.Exists(DropIn) || s.Read("/etc/ssh/sshd_config") != orig {
		t.Fatal("rollback did not restore the original configuration")
	}
	if !strings.Contains(s.Read("/root/.ssh/authorized_keys"), "ssh-ed25519") {
		t.Fatal("the added key is kept on rollback (like ssh-setup.sh)")
	}
}

func chain(a, b func(string) (string, error, bool)) func(string) (string, error, bool) {
	return func(l string) (string, error, bool) {
		if out, err, ok := b(l); ok {
			return out, err, ok
		}
		return a(l)
	}
}

func TestQuickFormFollowsUsersModule(t *testing.T) {
	s := newServer(t)
	env := newEnv(s, &fakePrompt{})
	env.Quick = true
	env.Selected = func(id string) bool { return id == "users" }
	env.Answers.Users.Name = "admin"
	m := New()
	m.Form(env)
	if env.Answers.SSH.User != "" {
		t.Fatalf("quick form must leave the user to the users module, got %q", env.Answers.SSH.User)
	}
	// answered in the users form after the ssh form was built
	env.Answers.Users.Name = "deploy"
	p, err := m.Check(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.String(), "/home/deploy/.ssh/authorized_keys") {
		t.Fatalf("plan must use the users module admin:\n%s", p.String())
	}
}
