package config

import (
	"strings"
	"testing"
)

func TestParseKeepsDefaults(t *testing.T) {
	a, err := Parse([]byte("ssh:\n  port: 2222\nufw:\n  allow_http: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if a.SSH.Port != 2222 || !a.UFW.AllowHTTP {
		t.Fatalf("values not loaded: %+v", a.SSH)
	}
	if a.SSH.MaxAuthTries != 3 || a.SSH.TCPForwarding != "no" || !a.UFW.DockerFix {
		t.Fatal("defaults lost")
	}
}

func TestParseRejectsUnknownKeys(t *testing.T) {
	if _, err := Parse([]byte("ssh:\n  prot: 2222\n")); err == nil || !strings.Contains(err.Error(), "prot") {
		t.Fatalf("expected unknown key error, got %v", err)
	}
}

func TestParseEmpty(t *testing.T) {
	a, err := Parse(nil)
	if err != nil || a.Fail2ban.MaxRetry != 3 {
		t.Fatalf("empty file: %v %+v", err, a.Fail2ban)
	}
}

func TestRoundTrip(t *testing.T) {
	a := Default()
	a.SSH.Port = 40022
	a.Users.Password = "secret"
	b, err := Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "secret") {
		t.Fatal("plain password must never be saved")
	}
	back, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if back.SSH.Port != 40022 {
		t.Fatalf("port = %d", back.SSH.Port)
	}
}

// The documented example must stay loadable.
func TestExampleFile(t *testing.T) {
	a, err := Load("../../docs/answers.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if a.SSH.Port != 40022 || len(a.Modules) != 7 || a.Sysctl.SwapSize != "2G" {
		t.Fatalf("unexpected values: %+v", a)
	}
}
