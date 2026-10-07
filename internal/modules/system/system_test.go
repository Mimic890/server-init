package system

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

func TestUnattendedGolden(t *testing.T) {
	systest.Golden(t, "unattended-debian.conf", RenderUnattended("debian", false, "04:00"))
	systest.Golden(t, "unattended-ubuntu-reboot.conf", RenderUnattended("ubuntu", true, "03:30"))
}

func TestSetHostsName(t *testing.T) {
	in := "127.0.0.1\tlocalhost\n127.0.1.1\told old.example\n::1 ip6-localhost\n"
	if got := SetHostsName(in, "web1"); got != "127.0.0.1\tlocalhost\n127.0.1.1\tweb1\n::1 ip6-localhost\n" {
		t.Fatalf("got %q", got)
	}
	if got := SetHostsName("127.0.0.1 localhost\n", "web1"); got != "127.0.0.1 localhost\n127.0.1.1\tweb1\n" {
		t.Fatalf("append: %q", got)
	}
}

func TestParseUpgraded(t *testing.T) {
	out := "Reading package lists...\nInst libc6 ...\n12 upgraded, 2 newly installed, 0 to remove and 0 not upgraded.\n"
	if n := ParseUpgraded(out); n != 14 {
		t.Fatalf("n = %d", n)
	}
	if n := ParseUpgraded("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"); n != 0 {
		t.Fatal(n)
	}
}

func TestLocaleHelpers(t *testing.T) {
	gen := "# en_US.UTF-8 UTF-8\n# de_DE.UTF-8 UTF-8\n"
	if got := enableLocale(gen, "en_US.UTF-8 UTF-8"); got != "en_US.UTF-8 UTF-8\n# de_DE.UTF-8 UTF-8\n" {
		t.Fatalf("got %q", got)
	}
	if got := setLang("LANG=C.UTF-8\n", "en_US.UTF-8"); got != "LANG=en_US.UTF-8\n" {
		t.Fatalf("got %q", got)
	}
}

func setup(t *testing.T) (*systest.Host, *module.Env) {
	h := systest.New(t)
	h.Write("/etc/hostname", "old\n")
	h.Write("/etc/hosts", "127.0.0.1 localhost\n127.0.1.1 old\n")
	h.Write("/etc/default/locale", "LANG=C.UTF-8\n")
	h.Write("/var/lib/apt/lists/archive_noble_main_binary-amd64_Packages", "")
	h.Write("/usr/share/zoneinfo/Europe/Berlin", "TZif")
	h.Write("/usr/share/zoneinfo/Etc/UTC", "TZif")
	h.On("timedatectl show -p Timezone --value", "Etc/UTC\n")
	h.On("timedatectl show -p NTP --value", "no\n")
	h.On("apt-get -s", "3 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")
	h.On("apt-cache policy", "  Installed: (none)\n  Candidate: 1.0\n")
	h.On("apt-cache policy zellij", "")
	h.Fail("dpkg-query")
	h.Fail("systemctl is-active")
	h.Fail("systemd-detect-virt")
	a := config.Default()
	a.System.Hostname = "web1"
	a.System.Timezone = "Europe/Berlin"
	a.System.Locale = "C.UTF-8"
	a.System.Packages = []string{"curl", "zellij"}
	e := &module.Env{Answers: a, Facts: &facts.Facts{OSID: "ubuntu", Hostname: "old"}, Sys: h,
		Run: state.NewRun(h, time.Unix(0, 0).UTC()), Log: slog.New(slog.DiscardHandler)}
	return h, e.For("system")
}

func fakeZellij(t *testing.T, corrupt bool) {
	bin := []byte("#!zellij")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "zellij", Mode: 0o755, Size: int64(len(bin)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(bin)
	_ = tw.Close()
	_ = gz.Close()
	sum := sha256.Sum256(bin)
	if corrupt {
		sum[0] ^= 1
	}
	old := httpGet
	t.Cleanup(func() { httpGet = old })
	httpGet = func(_ context.Context, url string) ([]byte, error) {
		if strings.HasSuffix(url, ".sha256sum") {
			return []byte(hex.EncodeToString(sum[:]) + "  target/zellij\n"), nil
		}
		return buf.Bytes(), nil
	}
}

func TestCheckAndApply(t *testing.T) {
	h, env := setup(t)
	fakeZellij(t, false)
	m := New()
	p, err := m.Check(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	text := p.String()
	for _, want := range []string{"full-upgrade (3 packages", "hostname: old -> web1", "timezone: Etc/UTC -> Europe/Berlin",
		"systemd-timesyncd", "security updates only", "install curl", "install zellij"} {
		if !strings.Contains(text, want) {
			t.Errorf("plan misses %q:\n%s", want, text)
		}
	}
	if err := m.Apply(context.Background(), env, p); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"apt-get full-upgrade -y", "hostnamectl set-hostname web1", "timedatectl set-timezone Europe/Berlin",
		"timedatectl set-ntp true", "apt-get install --no-install-recommends -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold curl"} {
		if !h.Ran(want) {
			t.Errorf("not run: %s", want)
		}
	}
	if h.Read(zellijBin) != "#!zellij" {
		t.Fatal("zellij not installed")
	}
	if !strings.Contains(h.Read("/etc/hosts"), "127.0.1.1\tweb1") {
		t.Fatal(h.Read("/etc/hosts"))
	}
}

func TestZellijChecksumMismatch(t *testing.T) {
	h, env := setup(t)
	fakeZellij(t, true)
	if err := New().Apply(context.Background(), env, module.Plan{}); err != nil {
		t.Fatal(err)
	}
	if h.Exists(zellijBin) {
		t.Fatal("a binary with a wrong checksum must not be installed")
	}
}

func TestValidation(t *testing.T) {
	_, env := setup(t)
	env.Answers.System.Timezone = "Mars/Base"
	if _, err := New().Check(context.Background(), env); err == nil {
		t.Fatal("unknown timezone accepted")
	}
	env.Answers.System.Timezone = "Etc/UTC"
	env.Answers.System.Hostname = "Bad_Name"
	if _, err := New().Check(context.Background(), env); err == nil {
		t.Fatal("bad hostname accepted")
	}
}

func TestEmptyAptListsPlansInstall(t *testing.T) {
	h, env := setup(t)
	_ = h.RemoveAll("/var/lib/apt/lists")
	h.On("apt-cache policy", "")
	p, err := New().Check(context.Background(), env)
	if err != nil || !strings.Contains(p.String(), "install curl") || strings.Contains(p.String(), "not available") {
		t.Fatalf("%v\n%s", err, p.String())
	}
}
