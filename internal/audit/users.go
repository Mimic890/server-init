package audit

import (
	"strings"

	"github.com/mimic890/server-init/internal/check"
)

func (h *host) userChecks() {
	passwd := h.read("/etc/passwd")
	shadow := h.read("/etc/shadow")
	if passwd == "" {
		h.add(catUsers, "Accounts", check.Skip, "cannot read /etc/passwd", nil, "")
		return
	}
	sudoers := h.read("/etc/sudoers")
	files, _ := h.s.Glob("/etc/sudoers.d/*")
	for _, f := range files {
		sudoers += "\n" + h.read(f)
	}
	UserChecks(h.r, passwd, shadow, sudoers)
}

// UserChecks judges /etc/passwd, /etc/shadow and the sudoers files.
func UserChecks(r *check.Report, passwd, shadow, sudoers string) {
	add := func(title string, st check.Status, summary string, details []string, fix string) {
		r.Add(check.Finding{Category: catUsers, Title: title, Status: st, Summary: summary, Details: details, Fix: fix})
	}

	var uid0, logins []string
	for _, l := range strings.Split(passwd, "\n") {
		f := strings.Split(l, ":")
		if len(f) < 7 {
			continue
		}
		if f[2] == "0" && f[0] != "root" {
			uid0 = append(uid0, f[0])
		}
		shell := f[6]
		if !strings.HasSuffix(shell, "nologin") && !strings.HasSuffix(shell, "/false") && shell != "/bin/sync" && shell != "" {
			if f[0] == "root" || len(f[2]) >= 4 { // root and uid >= 1000
				logins = append(logins, f[0]+" ("+shell+")")
			}
		}
	}
	if len(uid0) > 0 {
		add("Extra root accounts", check.Fail, "more accounts with UID 0 (full root rights)", uid0, "remove them or give them another UID")
	} else {
		add("Extra root accounts", check.OK, "only root has UID 0", nil, "")
	}
	add("Login accounts", check.Info, strings.Join(logins, ", "), nil, "")

	if shadow == "" {
		add("Passwords", check.Skip, "cannot read /etc/shadow (run as root)", nil, "")
	} else {
		var empty []string
		rootLocked := true
		for _, l := range strings.Split(shadow, "\n") {
			f := strings.Split(l, ":")
			if len(f) < 2 {
				continue
			}
			if f[1] == "" {
				empty = append(empty, f[0])
			}
			if f[0] == "root" {
				rootLocked = strings.HasPrefix(f[1], "!") || strings.HasPrefix(f[1], "*")
			}
		}
		if len(empty) > 0 {
			add("Empty passwords", check.Fail, "these accounts have no password at all", empty, "passwd -l <user>")
		} else {
			add("Empty passwords", check.OK, "none", nil, "")
		}
		if rootLocked {
			add("Root password", check.OK, "locked", nil, "")
		} else {
			add("Root password", check.Warn, "root has a usable password; with SSH keys it is not needed", nil, fixUsers)
		}
	}

	var nopw []string
	for _, l := range lines(sudoers) {
		if strings.Contains(l, "NOPASSWD") {
			nopw = append(nopw, l)
		}
	}
	if len(nopw) > 0 {
		add("sudo without password", check.Info, "fine when SSH keys are the only way in", nopw, "")
	}
}
