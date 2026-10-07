package sys

import (
	"context"
	"regexp"
	"strings"
)

// UserNameRe is the user name rule used by the original ssh-setup.sh.
var UserNameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// Passwd is one /etc/passwd entry.
type Passwd struct {
	Name, Home, Shell string
	UID, GID          string
}

// LookupUser returns the passwd entry of name (via getent, so LDAP/NSS users
// work as well).
func LookupUser(ctx context.Context, s System, name string) (Passwd, bool) {
	out, err := s.Query(ctx, "getent", "passwd", name)
	if err != nil {
		return Passwd{}, false
	}
	f := strings.Split(strings.TrimSpace(out), ":")
	if len(f) < 7 {
		return Passwd{}, false
	}
	return Passwd{Name: f[0], UID: f[2], GID: f[3], Home: f[5], Shell: f[6]}, true
}

// PrimaryGroup returns the name of the user's primary group.
func PrimaryGroup(ctx context.Context, s System, name string) string {
	out, err := s.Query(ctx, "id", "-gn", name)
	if err != nil {
		return name
	}
	return strings.TrimSpace(out)
}

// UserGroups returns the supplementary groups of a user.
func UserGroups(ctx context.Context, s System, name string) []string {
	out, err := s.Query(ctx, "id", "-nG", name)
	if err != nil {
		return nil
	}
	return strings.Fields(out)
}

// GroupExists reports whether a group exists.
func GroupExists(ctx context.Context, s System, name string) bool {
	_, err := s.Query(ctx, "getent", "group", name)
	return err == nil
}
