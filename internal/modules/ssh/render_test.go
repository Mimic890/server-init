package ssh

import (
	"strings"
	"testing"

	"github.com/mimic890/server-init/internal/systest"
)

func fullParams() Params {
	return Params{
		Ports:           []int{22, 40022},
		RootLogin:       "no",
		MaxAuthTries:    3,
		LoginGraceTime:  30,
		ClientAlive:     true,
		X11Forwarding:   false,
		TCPForwarding:   "local",
		AgentForwarding: true,
		Banner:          true,
		AllowUser:       "admin",
		Kex:             wantKex,
		Ciphers:         wantCiphers,
		MACs:            wantMACs,
	}
}

func TestRenderConfigGolden(t *testing.T) {
	systest.Golden(t, "sshd-full.conf", RenderConfig(fullParams()))
	p := fullParams()
	p.Ports = []int{40022}
	p.RootLogin = "prohibit-password"
	p.ClientAlive, p.Banner, p.AllowUser, p.AgentForwarding, p.TCPForwarding = false, false, "", false, "no"
	systest.Golden(t, "sshd-minimal.conf", RenderConfig(p))
}

func TestRenderSocketGolden(t *testing.T) {
	systest.Golden(t, "ssh-socket.conf", RenderSocket([]int{22, 40022}))
}

func TestRenderRollbackGolden(t *testing.T) {
	systest.Golden(t, "rollback-ssh.sh", RenderRollback([]RestoreStep{
		{Path: DropIn},
		{Path: SocketDropIn},
		{Path: "/etc/ssh/sshd_config", Backup: "/var/lib/server-init/backup-1/files/etc/ssh/sshd_config"},
	}))
}

func TestNeutralizePorts(t *testing.T) {
	in := "Include /etc/ssh/sshd_config.d/*.conf\n#Port 22\nPort 22\n  port 2222\nPorts are fun\n"
	got, changed := NeutralizePorts(in)
	want := "Include /etc/ssh/sshd_config.d/*.conf\n#Port 22\n# disabled by server-init: Port 22\n# disabled by server-init:   port 2222\nPorts are fun\n"
	if !changed || got != want {
		t.Fatalf("got:\n%s", got)
	}
	if _, changed := NeutralizePorts(got); changed {
		t.Fatal("second pass must not change anything")
	}
}

func TestFilterAlgs(t *testing.T) {
	h := systest.New(t)
	h.On("ssh -Q kex", "curve25519-sha256\ncurve25519-sha256@libssh.org\ndiffie-hellman-group14-sha256\n")
	got := FilterAlgs(t.Context(), h, "kex", wantKex)
	if got != "curve25519-sha256,curve25519-sha256@libssh.org" {
		t.Fatalf("got %q", got)
	}
	if !strings.Contains(FilterAlgs(t.Context(), h, "mac", wantMACs), "hmac-sha2-512-etm") {
		t.Fatal("unknown query output must keep the list")
	}
}
