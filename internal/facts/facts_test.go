package facts

import "testing"

func TestParseOSRelease(t *testing.T) {
	id, ver, pretty := ParseOSRelease(`PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
`)
	if id != "ubuntu" || ver != "24.04" || pretty != "Ubuntu 24.04.1 LTS" {
		t.Fatalf("got %q %q %q", id, ver, pretty)
	}
}

func TestSupported(t *testing.T) {
	cases := []struct {
		id, ver string
		ok      bool
	}{
		{"debian", "12", true},
		{"debian", "13", true},
		{"debian", "11", false},
		{"ubuntu", "24.04", true},
		{"ubuntu", "24.10", true},
		{"ubuntu", "26.04", true},
		{"ubuntu", "22.04", false},
		{"fedora", "40", false},
	}
	for _, c := range cases {
		if got := Supported(c.id, c.ver); got != c.ok {
			t.Errorf("Supported(%s, %s) = %v", c.id, c.ver, got)
		}
	}
}
