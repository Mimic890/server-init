package users

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/mimic890/server-init/internal/config"
	"github.com/mimic890/server-init/internal/facts"
	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/modules/shared"
	"github.com/mimic890/server-init/internal/state"
	"github.com/mimic890/server-init/internal/systest"
)

func TestEmptyPasswords(t *testing.T) {
	shadow := "root:!:19000:0:99999:7:::\nbob::19000:0:99999:7:::\nsvc:*:19000::::::\n"
	if got := EmptyPasswords(shadow); len(got) != 1 || got[0] != "bob" {
		t.Fatalf("got %v", got)
	}
}

func TestSetUmask(t *testing.T) {
	in := "# comment\nUMASK\t\t022\nHOME_MODE\t0750\n"
	if got := SetUmask(in, "027"); got != "# comment\nUMASK\t\t027\nHOME_MODE\t0750\n" {
		t.Fatalf("got %q", got)
	}
	if got := SetUmask("X 1\n", "027"); got != "X 1\nUMASK\t\t027\n" {
		t.Fatalf("append: %q", got)
	}
}

func setup(t *testing.T) (*systest.Host, *module.Env) {
	h := systest.New(t)
	h.Write("/etc/login.defs", "UMASK\t\t022\n")
	h.Write(CommonSession, "session required pam_unix.so\n") // Debian: no pam_umask
	h.Write("/etc/shadow", "root:$6$x:1:0:99999:7:::\nold::1:0:99999:7:::\n")
	h.Fail("getent passwd admin")
	h.On("getent group sudo", "sudo:x:27:")
	h.Fail("getent group docker")
	h.On("passwd -S root", "root P 2026-01-01 0 99999 7 -1")
	a := config.Default()
	a.Users.ExtraGroups = []string{"docker"}
	e := &module.Env{Answers: a, Facts: &facts.Facts{IsRoot: true}, Sys: h,
		Run: state.NewRun(h, time.Unix(0, 0).UTC()), Log: slog.New(slog.DiscardHandler)}
	return h, e.For("users")
}

func TestCheckAndApply(t *testing.T) {
	h, env := setup(t)
	m := New()
	p, err := m.Check(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	text := p.String()
	for _, want := range []string{"create user admin", "add admin to group sudo", "NOPASSWD", "lock the root password",
		"lock account old: it has an EMPTY password", "UMASK 027", "group docker does not exist", "enable pam_umask"} {
		if !strings.Contains(text, want) {
			t.Errorf("plan misses %q:\n%s", want, text)
		}
	}
	if err := m.Apply(context.Background(), env, p); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"adduser --disabled-password --gecos '' --shell /bin/bash admin", "usermod -c umask=027 admin",
		"visudo -cf /etc/sudoers.d/.server-init-check", "passwd -l root", "passwd -l old", "pam-auth-update --package"} {
		if !h.Ran(want) {
			t.Errorf("not run: %s\n%v", want, h.Cmds)
		}
	}
	if h.Read(shared.SudoersFile("admin")) != shared.RenderSudoers("admin", true) {
		t.Fatal("sudoers drop-in")
	}
	if !strings.Contains(h.Read("/etc/login.defs"), "UMASK\t\t027") {
		t.Fatal("umask")
	}
}

func TestSudoWithPasswordNeedsPassword(t *testing.T) {
	_, env := setup(t)
	env.Answers.Users.SudoNoPassword = false
	if _, err := New().Check(context.Background(), env); err == nil || !strings.Contains(err.Error(), "needs a password") {
		t.Fatalf("err = %v", err)
	}
	env.Answers.Users.Password = "correct horse"
	if _, err := New().Check(context.Background(), env); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordGoesToStdinOnly(t *testing.T) {
	h, env := setup(t)
	env.Answers.Users.SudoNoPassword = false
	env.Answers.Users.Password = "correct horse"
	if err := New().Apply(context.Background(), env, module.Plan{}); err != nil {
		t.Fatal(err)
	}
	for _, c := range h.Cmds {
		if strings.Contains(c, "correct horse") {
			t.Fatalf("password visible in a command line: %s", c)
		}
	}
	if !h.Ran("chpasswd") {
		t.Fatal("chpasswd not run")
	}
}

func TestKeepRoot(t *testing.T) {
	_, env := setup(t)
	env.Answers.Users.CreateAdmin = false
	env.Answers.Users.LockRoot = false
	p, err := New().Check(context.Background(), env)
	if err != nil || strings.Contains(p.String(), "admin") {
		t.Fatalf("%v\n%s", err, p.String())
	}
}

func TestUbuntuHasPamUmask(t *testing.T) {
	h, env := setup(t)
	h.Write(CommonSession, "session optional\t\t\tpam_umask.so\n")
	p, _ := New().Check(context.Background(), env)
	if strings.Contains(p.String(), "enable pam_umask") {
		t.Fatal("pam_umask already active, nothing to add")
	}
}
