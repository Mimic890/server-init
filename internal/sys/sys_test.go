package sys

import (
	"context"
	"strings"
	"testing"
)

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"plain":       "plain",
		"":            "''",
		"a b":         "'a b'",
		"it's":        `'it'\''s'`,
		"--opt=1,2":   "--opt=1,2",
		"sport = :22": "'sport = :22'",
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSetBlock(t *testing.T) {
	block := MarkedBlock("swap", "/swapfile none swap sw 0 0")
	in := "UUID=x / ext4 defaults 0 1\n"
	got := SetBlock(in, "swap", block, "")
	want := in + "# BEGIN server-init swap\n/swapfile none swap sw 0 0\n# END server-init swap\n"
	if got != want {
		t.Fatalf("append:\n%s", got)
	}
	if again := SetBlock(got, "swap", block, ""); again != got {
		t.Fatalf("not idempotent:\n%s", again)
	}
	repl := SetBlock(got, "swap", MarkedBlock("swap", "/other none swap sw 0 0"), "")
	if !strings.Contains(repl, "/other") || strings.Contains(repl, "/swapfile") {
		t.Fatalf("replace:\n%s", repl)
	}
	if removed := SetBlock(got, "swap", "", ""); removed != in {
		t.Fatalf("remove:\n%q", removed)
	}
	// insert before a line
	rules := "*filter\n:ufw-after-input - [0:0]\nCOMMIT\n"
	ins := SetBlock(rules, "docker", MarkedBlock("docker", "-A X"), "COMMIT")
	if !strings.HasSuffix(ins, "# END server-init docker\nCOMMIT\n") {
		t.Fatalf("insert before:\n%s", ins)
	}
	if !HasBlock(ins, "docker") || HasBlock(ins, "swap") {
		t.Fatal("HasBlock")
	}
}

func TestDiff(t *testing.T) {
	if Diff("/etc/x", "a\n", "a\n") != "" {
		t.Fatal("equal content must have no diff")
	}
	d := Diff("/etc/x", "", "new\n")
	if !strings.Contains(d, "--- /dev/null") || !strings.Contains(d, "+new") {
		t.Fatalf("diff:\n%s", d)
	}
}

func TestParseSSListeners(t *testing.T) {
	out := `LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=1,fd=3))
LISTEN 0      128             [::]:22           [::]:*    users:(("sshd",pid=1,fd=4))
LISTEN 0      4096         0.0.0.0:2222      0.0.0.0:*    users:(("systemd",pid=1,fd=50))
LISTEN 0      511          0.0.0.0:80        0.0.0.0:*    users:(("nginx",pid=9,fd=6))`
	if got := ParseSSListeners(out, `"sshd"`); len(got) != 1 || got[0] != 22 {
		t.Fatalf("sshd ports = %v", got)
	}
	if got := ParseSSListeners(out, `"systemd"`); len(got) != 1 || got[0] != 2222 {
		t.Fatalf("systemd ports = %v", got)
	}
}

func TestValidIPOrCIDR(t *testing.T) {
	for _, ok := range []string{"203.0.113.7", "10.0.0.0/8", "2001:db8::1", "2001:db8::/32"} {
		if !ValidIPOrCIDR(ok) {
			t.Errorf("%s should be valid", ok)
		}
	}
	for _, bad := range []string{"", "300.1.1.1", "1.2.3.4/33", "host.example", "1.2.3"} {
		if ValidIPOrCIDR(bad) {
			t.Errorf("%s should be invalid", bad)
		}
	}
}

func TestDryRunDoesNotWrite(t *testing.T) {
	root := t.TempDir()
	base := &Real{Root: root, SkipChown: true, Exec: func(context.Context, Cmd) (string, error) {
		t.Fatal("dry run must not execute changing commands")
		return "", nil
	}}
	var rec []string
	d := NewDryRun(base, func(s string) { rec = append(rec, s) })
	if err := d.WriteFile("/etc/test.conf", []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Run(context.Background(), Command("systemctl", "restart", "ssh")); err != nil {
		t.Fatal(err)
	}
	if Exists(base, "/etc/test.conf") {
		t.Fatal("file was written")
	}
	if got := ReadString(d, "/etc/test.conf"); got != "x\n" {
		t.Fatalf("dry run must remember pending writes, got %q", got)
	}
	if len(rec) != 2 || !strings.Contains(rec[0], "+x") || rec[1] != "$ systemctl restart ssh" {
		t.Fatalf("recorded: %q", rec)
	}
}

func TestRealWriteFileAtomic(t *testing.T) {
	r := &Real{Root: t.TempDir(), SkipChown: true}
	if err := r.WriteFile("/etc/a/b.conf", []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := r.Stat("/etc/a/b.conf")
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("stat: %v %v", st, err)
	}
	m, _ := r.Glob("/etc/a/*")
	if len(m) != 1 || m[0] != "/etc/a/b.conf" {
		t.Fatalf("glob = %v (temp files left behind?)", m)
	}
}
