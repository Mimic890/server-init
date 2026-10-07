package sysctl

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
	systest.Golden(t, "sysctl-strict.conf", Render(Params{BBR: true, Hardening: true, StrictRP: true, Swappiness: 10}))
	systest.Golden(t, "sysctl-loose-nobbr.conf", Render(Params{Hardening: true, Swappiness: 30}))
}

func TestSwapBytes(t *testing.T) {
	if n, ok := swapBytes("2G"); !ok || n != 2<<30 {
		t.Fatal(n)
	}
	if n, ok := swapBytes("512M"); !ok || n != 512<<20 {
		t.Fatal(n)
	}
	if _, ok := swapBytes("2T"); ok {
		t.Fatal("2T accepted")
	}
}

func setup(t *testing.T) (*systest.Host, *module.Env) {
	h := systest.New(t)
	h.Write("/proc/sys/net/ipv4/tcp_available_congestion_control", "reno cubic bbr\n")
	h.Write("/proc/swaps", "Filename Type Size Used Priority\n")
	h.Write("/etc/fstab", "UUID=x / ext4 defaults 0 1\n")
	h.Write("/sys/class/net/eth0/x", "")
	h.Hook = func(line string) (string, error, bool) {
		if strings.HasPrefix(line, "fallocate ") {
			h.Write(SwapFile, "")
			return "", nil, true
		}
		return "", nil, false
	}
	a := config.Default()
	a.Sysctl.SwapSize = "1G"
	e := &module.Env{Answers: a, Facts: &facts.Facts{FreeDiskMB: 20000}, Sys: h,
		Run: state.NewRun(h, time.Unix(0, 0).UTC()), Log: slog.New(slog.DiscardHandler)}
	return h, e.For("sysctl")
}

func TestCheckApplyRollback(t *testing.T) {
	h, env := setup(t)
	m := New()
	p, err := m.Check(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	text := p.String()
	for _, want := range []string{"+net.ipv4.tcp_congestion_control = bbr", "+net.ipv4.conf.all.rp_filter = 1", "swap file /swapfile of 1G"} {
		if !strings.Contains(text, want) {
			t.Errorf("plan misses %q:\n%s", want, text)
		}
	}
	if err := m.Apply(context.Background(), env, p); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"fallocate -l 1073741824 /swapfile", "mkswap /swapfile", "swapon /swapfile", "sysctl -p " + DropIn} {
		if !h.Ran(want) {
			t.Errorf("not run: %s", want)
		}
	}
	if !strings.Contains(h.Read("/etc/fstab"), "/swapfile none swap sw 0 0") {
		t.Fatal("fstab")
	}
	// the kernel now reports the swap file
	h.Write("/proc/swaps", "Filename Type Size Used Priority\n/swapfile file 1048572 0 -2\n")
	if p, _ := m.Check(context.Background(), env); !p.Empty() {
		t.Fatalf("rerun must be a no-op:\n%s", p.String())
	}
	h.Reset()
	if err := m.Rollback(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	order := []string{}
	for _, c := range h.Cmds {
		if strings.HasPrefix(c, "swapoff") || strings.HasPrefix(c, "rm -f /swapfile") || strings.HasPrefix(c, "sysctl --system") {
			order = append(order, strings.Fields(c)[0])
		}
	}
	if strings.Join(order, ",") != "sysctl,swapoff,rm" {
		t.Fatalf("rollback order = %v", order)
	}
	if strings.Contains(h.Read("/etc/fstab"), "swapfile") || h.Exists(DropIn) {
		t.Fatal("files not restored")
	}
}

func TestLooseRPWithVPN(t *testing.T) {
	h, env := setup(t)
	h.Write("/sys/class/net/tailscale0/x", "")
	p, _ := New().Check(context.Background(), env)
	if !strings.Contains(p.String(), "rp_filter = 2") {
		t.Fatalf("plan:\n%s", p.String())
	}
}

func TestNoBBRKernel(t *testing.T) {
	h, env := setup(t)
	h.Write("/proc/sys/net/ipv4/tcp_available_congestion_control", "reno cubic\n")
	h.Fail("uname -r")
	p, _ := New().Check(context.Background(), env)
	if strings.Contains(p.String(), "bbr") || len(p.Notes) == 0 {
		t.Fatalf("plan:\n%s", p.String())
	}
}

func TestExistingSwap(t *testing.T) {
	h, env := setup(t)
	h.Write("/proc/swaps", "Filename Type Size Used Priority\n/dev/sda2 partition 1 0 -2\n")
	p, _ := New().Check(context.Background(), env)
	if strings.Contains(p.String(), "swap file /swapfile of") {
		t.Fatal("must not create a swap file when swap exists")
	}
}

func TestSwapTooBig(t *testing.T) {
	_, env := setup(t)
	env.Facts.FreeDiskMB = 1500
	env.Answers.Sysctl.SwapSize = "2G"
	if _, err := New().Check(context.Background(), env); err == nil {
		t.Fatal("swap larger than the free disk accepted")
	}
}
