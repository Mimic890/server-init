package system

import (
	"fmt"
	"strings"
)

// Files written by the module.
const (
	AutoUpgrades = "/etc/apt/apt.conf.d/20auto-upgrades"
	Unattended   = "/etc/apt/apt.conf.d/52server-init-unattended"
	HostsFile    = "/etc/hosts"
)

// RenderAutoUpgrades enables the daily apt timers.
func RenderAutoUpgrades() string {
	return `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
`
}

// RenderUnattended limits unattended-upgrades to security updates. It is
// loaded after the distribution's 50unattended-upgrades, whose origin lists
// are cleared first (#clear), so only the lines below count.
func RenderUnattended(osID string, reboot bool, rebootTime string) string {
	var b strings.Builder
	b.WriteString("// Managed by server-init: security updates only.\n")
	b.WriteString("#clear Unattended-Upgrade::Allowed-Origins;\n#clear Unattended-Upgrade::Origins-Pattern;\n")
	b.WriteString("Unattended-Upgrade::Origins-Pattern {\n")
	if osID == "ubuntu" {
		b.WriteString(`        "origin=Ubuntu,archive=${distro_codename}-security";
        "origin=UbuntuESMApps,archive=${distro_codename}-apps-security";
        "origin=UbuntuESM,archive=${distro_codename}-infra-security";
`)
	} else {
		b.WriteString(`        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
        "origin=Debian,codename=${distro_codename},label=Debian-Security";
`)
	}
	b.WriteString("};\n")
	fmt.Fprintf(&b, "Unattended-Upgrade::Automatic-Reboot \"%t\";\n", reboot)
	if reboot {
		fmt.Fprintf(&b, "Unattended-Upgrade::Automatic-Reboot-Time \"%s\";\n", rebootTime)
	}
	return b.String()
}

// SetHostsName makes the 127.0.1.1 line of /etc/hosts name the host (the
// Debian convention, so sudo and other tools resolve the hostname).
func SetHostsName(content, name string) string {
	lines := strings.SplitAfter(content, "\n")
	for i, l := range lines {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "127.0.1.1" {
			lines[i] = "127.0.1.1\t" + name + "\n"
			return strings.Join(lines, "")
		}
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + "127.0.1.1\t" + name + "\n"
}
