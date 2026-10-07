package audit

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/mimic890/server-init/internal/check"
)

// ParseSSHDConfig parses `sshd -T` output into lowercase keys. Repeated
// keys (port, listenaddress) are joined with a space.
func ParseSSHDConfig(out string) map[string]string {
	cfg := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), " ")
		if !ok {
			continue
		}
		k = strings.ToLower(k)
		if old, ok := cfg[k]; ok {
			v = old + " " + v
		}
		cfg[k] = v
	}
	return cfg
}

// Weak algorithms (ssh-audit / Mozilla guidelines).
var (
	weakCiphers = []string{"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128", "arcfour256"}
	weakMACs    = []string{"hmac-md5", "hmac-md5-96", "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com",
		"hmac-sha1", "hmac-sha1-96", "hmac-sha1-etm@openssh.com", "hmac-sha1-96-etm@openssh.com",
		"umac-64@openssh.com", "umac-64-etm@openssh.com"}
	weakKex = []string{"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}
)

func weakIn(list string, weak []string) []string {
	var out []string
	for _, a := range strings.Split(list, ",") {
		if slices.Contains(weak, strings.TrimSpace(a)) {
			out = append(out, a)
		}
	}
	return out
}

func (h *host) sshChecks() {
	out, err := h.query("sshd", "-T")
	if err != nil {
		h.add(catSSH, "SSH server", check.Skip, "cannot read the effective sshd configuration (sshd -T)", nil, "")
		return
	}
	SSHChecks(h.r, ParseSSHDConfig(out))
}

// SSHChecks judges an effective sshd configuration.
func SSHChecks(r *check.Report, c map[string]string) {
	add := func(title string, st check.Status, summary string, details []string, fix string) {
		r.Add(check.Finding{Category: catSSH, Title: title, Status: st, Summary: summary, Details: details, Fix: fix})
	}

	switch c["permitrootlogin"] {
	case "yes":
		add("Root login", check.Fail, "root may log in with a password", nil, fixSSH)
	case "no":
		add("Root login", check.OK, "disabled", nil, "")
	default:
		add("Root login", check.OK, "keys only ("+c["permitrootlogin"]+")", nil, "")
	}

	var pw []string
	if c["passwordauthentication"] == "yes" {
		pw = append(pw, "PasswordAuthentication yes")
	}
	if c["kbdinteractiveauthentication"] == "yes" && c["usepam"] == "yes" {
		pw = append(pw, "KbdInteractiveAuthentication yes (passwords through PAM)")
	}
	switch {
	case c["permitemptypasswords"] == "yes":
		add("Password login", check.Fail, "accounts without a password can log in", []string{"PermitEmptyPasswords yes"}, fixSSH)
	case len(pw) > 0:
		add("Password login", check.Fail, "passwords are accepted, bots can brute-force them", pw, fixSSH)
	default:
		add("Password login", check.OK, "keys only", nil, "")
	}

	ports := strings.Fields(c["port"])
	if slices.Contains(ports, "22") {
		add("SSH port", check.Info, "22 - bots scan it all day (noise, not a hole by itself)", nil, "")
	} else if len(ports) > 0 {
		add("SSH port", check.OK, strings.Join(ports, ", "), nil, "")
	}

	var limits []string
	if n, err := strconv.Atoi(c["maxauthtries"]); err == nil && n > 6 {
		limits = append(limits, fmt.Sprintf("MaxAuthTries %d (recommended: 3-6)", n))
	}
	if n, err := strconv.Atoi(c["logingracetime"]); err == nil && (n == 0 || n > 120) {
		limits = append(limits, fmt.Sprintf("LoginGraceTime %d (recommended: 30-60)", n))
	}
	if len(limits) > 0 {
		add("Brute-force limits", check.Warn, "generous", limits, fixSSH)
	} else {
		add("Brute-force limits", check.OK, "", nil, "")
	}

	if c["x11forwarding"] == "yes" {
		add("X11 forwarding", check.Warn, "enabled, servers rarely need it", nil, fixSSH)
	}

	var weak []string
	for _, w := range weakIn(c["ciphers"], weakCiphers) {
		weak = append(weak, "cipher "+w)
	}
	for _, w := range weakIn(c["macs"], weakMACs) {
		weak = append(weak, "MAC "+w)
	}
	for _, w := range weakIn(c["kexalgorithms"], weakKex) {
		weak = append(weak, "key exchange "+w)
	}
	if len(weak) > 0 {
		add("Crypto", check.Warn, "weak algorithms are allowed", weak, fixSSH)
	} else {
		add("Crypto", check.OK, "modern algorithms only", nil, "")
	}

	if c["allowusers"] == "" && c["allowgroups"] == "" {
		add("Allowed users", check.Info, "every account with a key may log in (no AllowUsers)", nil, "")
	} else {
		add("Allowed users", check.OK, strings.TrimSpace(c["allowusers"]+" "+c["allowgroups"]), nil, "")
	}
}
