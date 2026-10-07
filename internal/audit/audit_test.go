package audit

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mimic890/server-init/internal/check"
	"github.com/mimic890/server-init/internal/systest"
)

func find(r check.Report, title string) (check.Finding, bool) {
	for _, f := range r.Findings {
		if f.Title == title {
			return f, true
		}
	}
	return check.Finding{}, false
}

func status(t *testing.T, r check.Report, title string, want check.Status) check.Finding {
	t.Helper()
	f, ok := find(r, title)
	if !ok {
		t.Fatalf("no finding %q in:\n%s", title, r.String())
	}
	if f.Status != want {
		t.Fatalf("%s: status %v, want %v\n%s", title, f.Status, want, r.String())
	}
	return f
}

const defaultSSHD = `port 22
permitrootlogin yes
passwordauthentication yes
kbdinteractiveauthentication no
usepam yes
permitemptypasswords no
maxauthtries 6
logingracetime 120
x11forwarding yes
ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes256-gcm@openssh.com
macs umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha1
kexalgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256
`

const hardenedSSHD = `port 40022
permitrootlogin no
passwordauthentication no
kbdinteractiveauthentication no
usepam yes
permitemptypasswords no
maxauthtries 3
logingracetime 30
x11forwarding no
ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
kexalgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256
allowusers admin
`

func TestSSHChecks(t *testing.T) {
	var r check.Report
	SSHChecks(&r, ParseSSHDConfig(defaultSSHD))
	status(t, r, "Root login", check.Fail)
	status(t, r, "Password login", check.Fail)
	status(t, r, "SSH port", check.Info)
	status(t, r, "X11 forwarding", check.Warn)
	crypto := status(t, r, "Crypto", check.Warn)
	if strings.Join(crypto.Details, ",") != "MAC umac-64-etm@openssh.com,MAC hmac-sha1" {
		t.Fatalf("weak algorithms: %v", crypto.Details)
	}

	r = check.Report{}
	SSHChecks(&r, ParseSSHDConfig(hardenedSSHD))
	if n := r.Count(check.Fail) + r.Count(check.Warn); n != 0 {
		t.Fatalf("hardened sshd must pass:\n%s", r.String())
	}
}

func TestUserChecks(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\nadmin:x:1000:1000::/home/admin:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n"
	shadow := "root:$y$hash:19000::::::\ntoor:!:19000::::::\nadmin::19000::::::\n"
	var r check.Report
	UserChecks(&r, passwd, shadow, "admin ALL=(ALL) NOPASSWD:ALL\n# %sudo NOPASSWD\n")
	if f := status(t, r, "Extra root accounts", check.Fail); f.Details[0] != "toor" {
		t.Fatal(f.Details)
	}
	if f := status(t, r, "Empty passwords", check.Fail); f.Details[0] != "admin" {
		t.Fatal(f.Details)
	}
	status(t, r, "Root password", check.Warn)
	if f := status(t, r, "sudo without password", check.Info); len(f.Details) != 1 {
		t.Fatal("comments must be ignored:", f.Details)
	}
	if f := status(t, r, "Login accounts", check.Info); !strings.Contains(f.Summary, "admin") || strings.Contains(f.Summary, "www-data") {
		t.Fatal(f.Summary)
	}
}

const ssOut = `tcp   LISTEN 0 128 0.0.0.0:40022 0.0.0.0:* users:(("sshd",pid=10,fd=3))
tcp   LISTEN 0 128 [::]:40022 [::]:* users:(("sshd",pid=10,fd=4))
tcp   LISTEN 0 80 127.0.0.1:3306 0.0.0.0:* users:(("mariadbd",pid=20,fd=20))
tcp   LISTEN 0 511 0.0.0.0:6379 0.0.0.0:* users:(("redis-server",pid=30,fd=6))
tcp   LISTEN 0 4096 0.0.0.0:5432 0.0.0.0:* users:(("docker-proxy",pid=40,fd=4))
tcp   LISTEN 0 511 *:443 *:* users:(("nginx",pid=50,fd=7))
udp   UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=60,fd=13))
`

func TestNetworkChecks(t *testing.T) {
	ls := ParseListeners(ssOut)
	if len(ls) != 7 || ls[0].Process != "sshd" || ls[0].Port != 40022 || ls[6].Public() || !ls[5].Public() {
		t.Fatalf("parsed: %+v", ls)
	}

	var r check.Report
	NetworkChecks(&r, ls, "", false)
	f := status(t, r, "Databases and admin services", check.Fail)
	if len(f.Details) != 2 || !strings.Contains(f.Details[0], "Redis") {
		t.Fatalf("no firewall: %v", f.Details)
	}

	ufw := "Status: active\nDefault: deny (incoming), allow (outgoing)\n\nTo Action From\n-- ------ ----\n40022/tcp LIMIT IN Anywhere\n443/tcp ALLOW IN Anywhere\n"
	r = check.Report{}
	NetworkChecks(&r, ls, ufw, false)
	f = status(t, r, "Databases and admin services", check.Fail)
	if len(f.Details) != 1 || !strings.Contains(f.Details[0], "bypasses ufw") {
		t.Fatalf("docker port must count as exposed: %v", f.Details)
	}

	r = check.Report{}
	NetworkChecks(&r, ls, ufw, true)
	f = status(t, r, "Databases and admin services", check.Warn)
	if len(f.Details) != 2 {
		t.Fatalf("blocked by ufw: %v", f.Details)
	}
	if !ufwAllows(ufw+"6000:6007/tcp ALLOW IN Anywhere\n", 6003, "tcp") || ufwAllows(ufw, 6379, "tcp") {
		t.Fatal("ufwAllows")
	}
}

func TestPendingUpdates(t *testing.T) {
	out := `Inst openssl [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Conf openssl (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst htop [3.3.0-4build1] (3.3.0-4ubuntu1 Ubuntu:24.04/noble-updates [amd64])
Inst libc6 [2.36-9+deb12u7] (2.36-9+deb12u9 Debian-Security:12/stable-security [amd64])
`
	all, sec := PendingUpdates(out)
	if strings.Join(all, " ") != "openssl htop libc6" || strings.Join(sec, " ") != "openssl libc6" {
		t.Fatal(all, sec)
	}
}

func TestParseFind(t *testing.T) {
	suid, ww := ParseFind("suid /usr/bin/passwd\nww /etc/evil.conf\nww /tmp/x\nsuid /tmp/.x/sh\n")
	if strings.Join(suid, " ") != "/usr/bin/passwd /tmp/.x/sh" || strings.Join(ww, " ") != "/etc/evil.conf" {
		t.Fatal(suid, ww)
	}
}

func TestWebChecks(t *testing.T) {
	var r check.Report
	NginxChecks(&r, "http {\n  autoindex on;\n  ssl_protocols TLSv1 TLSv1.2;\n}\n")
	status(t, r, "nginx version banner", check.Warn)
	status(t, r, "nginx directory listing", check.Warn)
	status(t, r, "nginx TLS versions", check.Warn)

	r = check.Report{}
	NginxChecks(&r, "http {\n  server_tokens off;\n  ssl_protocols TLSv1.2 TLSv1.3;\n}\n")
	if r.Count(check.Warn) != 0 {
		t.Fatal(r.String())
	}

	r = check.Report{}
	ApacheChecks(&r, "<Directory /var/www/>\n\tOptions Indexes FollowSymLinks\n</Directory>\nServerTokens OS\nServerSignature On\n")
	status(t, r, "Apache version banner", check.Warn)
	status(t, r, "Apache directory listing", check.Warn)

	day := 24 * time.Hour
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for left, want := range map[time.Duration]check.Status{-day: check.Fail, 5 * day: check.Warn, 60 * day: check.OK} {
		r = check.Report{}
		TLSCertCheck(&r, &x509.Certificate{NotAfter: t0.Add(left), DNSNames: []string{"example.com"}}, t0)
		status(t, r, "HTTPS certificate", want)
	}
}

func TestRunOnFakeHost(t *testing.T) {
	h := systest.New(t)
	h.Tools["ufw"] = true
	h.Tools["fail2ban-client"] = true
	h.On("sshd -T", hardenedSSHD)
	h.On("ss -H -tulpn", ssOut)
	h.On("ufw status verbose", "Status: active\nDefault: deny (incoming), allow (outgoing)\n40022/tcp LIMIT IN Anywhere\n443/tcp ALLOW IN Anywhere\n")
	h.On("fail2ban-client status", "Jail list: sshd, recidive")
	h.On("dpkg-query -W '-f=${Status}' unattended-upgrades", "install ok installed")
	h.On("timedatectl show -p NTPSynchronized", "yes\n")
	h.Fail("systemd-detect-virt")
	h.Write("/etc/apt/apt.conf.d/20auto-upgrades", `APT::Periodic::Unattended-Upgrade "1";`)
	h.Write("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
	h.Write("/etc/shadow", "root:!:19000::::::\n")
	h.Write("/proc/sys/net/ipv4/tcp_syncookies", "1\n")
	h.Write("/var/lib/dpkg/info/passwd.list", "/usr/bin/passwd\n")
	h.On("find / -xdev", "suid /usr/bin/passwd\nsuid /tmp/.x/rootshell\n")
	old := DialTLS
	DialTLS = func(context.Context, string, string, uint16) (*x509.Certificate, error) {
		return nil, errors.New("refused")
	}
	defer func() { DialTLS = old }()

	r := Run(context.Background(), h)
	status(t, r, "Firewall", check.OK)
	status(t, r, "fail2ban", check.OK)
	status(t, r, "Automatic security updates", check.OK)
	status(t, r, "Clock", check.OK)
	status(t, r, "Kernel settings", check.OK)
	if f := status(t, r, "SUID programs", check.Fail); strings.Join(f.Details, " ") != "/tmp/.x/rootshell" {
		t.Fatal(f.Details)
	}
	status(t, r, "HTTPS certificate", check.Skip)
	for _, c := range h.Cmds {
		for _, w := range []string{"apt-get install", "systemctl restart", "ufw enable"} {
			if strings.HasPrefix(c, w) {
				t.Fatalf("the audit must not change anything, ran %q", c)
			}
		}
	}
}
