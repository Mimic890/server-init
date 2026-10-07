package fail2ban

import (
	"fmt"
	"strings"
)

// Files written by the module (same layout as ssh-setup.sh, renamed).
const (
	JailFile      = "/etc/fail2ban/jail.d/server-init.local"
	WhitelistJail = "/etc/fail2ban/jail.d/server-init-whitelist.local"
	DBConf        = "/etc/fail2ban/fail2ban.d/server-init.local"
	FilterFile    = "/etc/fail2ban/filter.d/server-init-blacklist.conf"
	BlacklistLog  = "/var/log/server-init-blacklist.log"
	WhitelistList = "/etc/server-init/whitelist.list"
	BlacklistList = "/etc/server-init/blacklist.list"
	BlacklistJail = "server-init-blacklist"
)

// Files of ssh-setup.sh that are taken over.
var (
	legacyFiles = []string{
		"/etc/fail2ban/jail.d/ssh-setup.local",
		"/etc/fail2ban/jail.d/ssh-setup-whitelist.local",
		"/etc/fail2ban/fail2ban.d/ssh-setup.local",
		"/etc/fail2ban/filter.d/ssh-setup-blacklist.conf",
	}
	legacyWhitelist = "/etc/ssh-setup/whitelist.list"
	legacyBlacklist = "/etc/ssh-setup/blacklist.list"
)

// JailParams are the inputs of the jail file.
type JailParams struct {
	Ports    []int
	MaxRetry int
	FindTime string
	BanTime  string
	Recidive bool
}

// RenderJail renders jail.d/server-init.local (render_f2b_jail of
// ssh-setup.sh).
func RenderJail(p JailParams) string {
	ports := make([]string, len(p.Ports))
	for i, x := range p.Ports {
		ports[i] = fmt.Sprint(x)
	}
	var b strings.Builder
	fmt.Fprintf(&b, `# Managed by server-init
[sshd]
enabled = true
port = %s
filter = sshd[mode=aggressive]
backend = systemd
journalmatch = _SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service
maxretry = %d
findtime = %s
bantime = %s

[%s]
enabled = true
filter = %s
logpath = %s
backend = polling
maxretry = 1
findtime = 1d
bantime = -1
banaction = %%(banaction_allports)s
`, strings.Join(ports, ","), p.MaxRetry, p.FindTime, p.BanTime, BlacklistJail, BlacklistJail, BlacklistLog)
	if p.Recidive {
		b.WriteString(`
[recidive]
enabled = true
logpath = /var/log/fail2ban.log
backend = auto
maxretry = 3
findtime = 1d
bantime = 1w
`)
	} else {
		b.WriteString("\n[recidive]\nenabled = false\n")
	}
	return b.String()
}

// RenderWhitelist renders the ignoreip drop-in from the whitelist entries.
func RenderWhitelist(entries []string) string {
	ips := append([]string{"127.0.0.1/8", "::1"}, entries...)
	return "# Managed by server-init - edit with: server-init f2b whitelist add|del\n[DEFAULT]\nignoreip = " +
		strings.Join(ips, " ") + "\n"
}

// RenderDBConf raises the purge age so permanent bans survive.
func RenderDBConf() string { return "[Definition]\ndbpurgeage = 3650d\n" }

// RenderFilter is the filter of the manual blacklist jail; it never matches
// real logs.
func RenderFilter() string {
	return `# Used by server-init for manually blacklisted IPs (never matches real logs)
[Definition]
failregex = ^server-init-blacklist <HOST>$
ignoreregex =
datepattern = {NONE}
`
}

// ParseList reads a one-entry-per-line list.
func ParseList(content string) []string {
	var out []string
	for _, l := range strings.Split(content, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// RenderList writes a list.
func RenderList(entries []string) string {
	if len(entries) == 0 {
		return ""
	}
	return strings.Join(entries, "\n") + "\n"
}
