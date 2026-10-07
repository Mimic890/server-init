package shared

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
)

// Accepted public key types (ed25519 only, as in ssh-setup.sh).
const (
	KeyEd25519   = "ssh-ed25519"
	KeySkEd25519 = "sk-ssh-ed25519@openssh.com"
)

// ParsePublicKey validates one authorized_keys line with an ed25519 key and
// returns it normalized to "type base64 [comment]" (options are not
// accepted). The wire format is checked, not just the prefix.
func ParsePublicKey(line string) (string, error) {
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) < 2 {
		return "", errors.New("paste one line: ssh-ed25519 AAAA... comment")
	}
	typ := f[0]
	if typ != KeyEd25519 && typ != KeySkEd25519 {
		if strings.HasPrefix(typ, "ssh-") || strings.HasPrefix(typ, "ecdsa-") || strings.HasPrefix(typ, "sk-") {
			return "", errors.New("only ed25519 keys are accepted; create one with: ssh-keygen -t ed25519")
		}
		return "", errors.New("not a public key; paste the content of your .pub file")
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return "", errors.New("the key data is not valid base64")
	}
	r := bytes.NewReader(blob)
	name, err := readString(r)
	if err != nil || string(name) != typ {
		return "", errors.New("the key data does not match its type")
	}
	pub, err := readString(r)
	if err != nil || len(pub) != 32 {
		return "", errors.New("invalid ed25519 key length")
	}
	if typ == KeySkEd25519 {
		if app, err := readString(r); err != nil || len(app) == 0 {
			return "", errors.New("security key application is missing")
		}
	}
	if r.Len() != 0 {
		return "", errors.New("unexpected data after the key")
	}
	out := typ + " " + f[1]
	if len(f) > 2 {
		out += " " + f[2] // first word of the comment, like ssh-setup.sh
	}
	return out, nil
}

func readString(r *bytes.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if int(n) > r.Len() {
		return nil, errors.New("short")
	}
	b := make([]byte, n)
	_, err := r.Read(b)
	return b, err
}

// KeyData returns the base64 part of a public key line.
func KeyData(line string) string {
	f := strings.Fields(line)
	if len(f) < 2 {
		return ""
	}
	return f[1]
}

// HasKey reports whether authorized_keys content contains the key of line
// (compared by key data, comments and options are ignored).
func HasKey(authorizedKeys, line string) bool {
	data := KeyData(line)
	if data == "" {
		return false
	}
	for _, l := range strings.Split(authorizedKeys, "\n") {
		for _, f := range strings.Fields(l) {
			if f == data {
				return true
			}
		}
	}
	return false
}
