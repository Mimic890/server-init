package shared

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

func wire(parts ...[]byte) string {
	var b []byte
	for _, p := range parts {
		b = binary.BigEndian.AppendUint32(b, uint32(len(p)))
		b = append(b, p...)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestParsePublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	good := "ssh-ed25519 " + wire([]byte("ssh-ed25519"), pub) + " me@pc extra words"
	got, err := ParsePublicKey("  " + good + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Join(strings.Fields(good)[:3], " "); got != want {
		t.Fatalf("normalized = %q, want %q", got, want)
	}
	sk := "sk-ssh-ed25519@openssh.com " + wire([]byte("sk-ssh-ed25519@openssh.com"), pub, []byte("ssh:"))
	if _, err := ParsePublicKey(sk); err != nil {
		t.Fatalf("sk key: %v", err)
	}

	bad := map[string]string{
		"":                         "paste one line",
		"ssh-rsa AAAAB3NzaC1yc2E=": "only ed25519",
		"hello world":              "not a public key",
		"ssh-ed25519 !!!":          "base64",
		"ssh-ed25519 " + wire([]byte("ssh-rsa"), pub):          "does not match",
		"ssh-ed25519 " + wire([]byte("ssh-ed25519"), pub[:10]): "length",
	}
	for in, want := range bad {
		if _, err := ParsePublicKey(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParsePublicKey(%q) = %v, want error with %q", in, err, want)
		}
	}
}

func TestHasKey(t *testing.T) {
	ak := "ssh-ed25519 AAAAkey1 a@b\nfrom=\"1.2.3.4\" ssh-ed25519 AAAAkey2 c@d\n"
	if !HasKey(ak, "ssh-ed25519 AAAAkey2 other") || HasKey(ak, "ssh-ed25519 AAAAkey3") {
		t.Fatal("HasKey")
	}
}

func TestRenderSudoers(t *testing.T) {
	if got := RenderSudoers("admin", true); got != "# Managed by server-init\nadmin ALL=(ALL:ALL) NOPASSWD:ALL\n" {
		t.Fatalf("got %q", got)
	}
}
