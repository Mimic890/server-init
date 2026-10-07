// Package audit checks the security of the host without changing anything:
// SSH, accounts, open ports, firewall, fail2ban, updates, kernel settings,
// file permissions and web servers.
package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/mimic890/server-init/internal/check"
	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/sys"
)

// Categories in report order.
const (
	catSSH      = "SSH"
	catUsers    = "Accounts"
	catNetwork  = "Network"
	catFirewall = "Firewall and fail2ban"
	catUpdates  = "Updates"
	catKernel   = "Kernel"
	catFiles    = "Files"
	catWeb      = "Web server"
)

// Fix hints point into the menu.
const (
	fixSSH      = "server-init → Manage → SSH"
	fixUsers    = "server-init → Manage → Admin user"
	fixFirewall = "server-init → Manage → Firewall"
	fixF2B      = "server-init → Manage → fail2ban settings"
	fixSystem   = "server-init → Custom setup → System basics"
	fixSysctl   = "server-init → Custom setup → Kernel and swap"
)

// host is what the checks share.
type host struct {
	ctx context.Context
	s   sys.System
	r   *check.Report
	// listeners is the parsed `ss -tulpn` output (nil when unavailable).
	listeners []listener
	ufwStatus string // `ufw status verbose`, "" when ufw is inactive
}

func (h *host) add(cat, title string, st check.Status, summary string, details []string, fix string) {
	h.r.Add(check.Finding{Category: cat, Title: title, Status: st, Summary: summary, Details: details, Fix: fix})
}

func (h *host) query(name string, args ...string) (string, error) {
	return h.s.Query(h.ctx, name, args...)
}

func (h *host) read(path string) string { return sys.ReadString(h.s, path) }

// Run audits the host. It only reads.
func Run(ctx context.Context, s sys.System) check.Report {
	start := time.Now()
	r := &check.Report{Title: "Security audit"}
	h := &host{ctx: ctx, s: s, r: r}
	h.loadNetwork()
	h.sshChecks()
	h.userChecks()
	h.networkChecks()
	h.firewallChecks()
	h.updateChecks()
	h.kernelChecks()
	h.fileChecks()
	h.webChecks()
	r.Duration = time.Since(start)
	return *r
}

// Command implements `server-init audit`.
func Command(ctx context.Context, env *module.Env, args []string, out io.Writer) error {
	if len(args) > 0 {
		return errors.New("usage: server-init audit")
	}
	if !env.Facts.IsRoot {
		return errors.New("run as root: most checks read root-only files")
	}
	r := Run(ctx, env.Sys)
	check.Render(out, r, check.Plain)
	if n := r.Count(check.Fail); n > 0 {
		return fmt.Errorf("%d problem(s) found", n)
	}
	return nil
}

// lines returns the non-empty, non-comment lines of s.
func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}
