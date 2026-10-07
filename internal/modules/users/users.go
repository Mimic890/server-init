// Package users creates the admin account (or keeps root, key-only), grants
// sudo through a validated drop-in, locks the root password and accounts
// with empty passwords, fixes SSH directory permissions and sets umask 027.
package users

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"charm.land/huh/v2"

	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/modules/shared"
	"github.com/mimic890/server-init/internal/sys"
)

// LoginDefs holds UMASK (applied by pam_umask to all sessions).
const LoginDefs = "/etc/login.defs"

// pam_umask is in Ubuntu's common-session but not in Debian's; there it is
// added through a pam-auth-update profile (Debian's drop-in for common-*).
const (
	CommonSession  = "/etc/pam.d/common-session"
	UmaskProfile   = "/usr/share/pam-configs/server-init-umask"
	umaskProfileID = "server-init-umask"
)

// RenderUmaskProfile is the pam-auth-update profile that enables pam_umask.
func RenderUmaskProfile() string {
	return `Name: umask from /etc/login.defs and GECOS (server-init)
Default: yes
Priority: 0
Session-Type: Additional
Session-Interactive-Only: no
Session:
	optional			pam_umask.so
`
}

func pamUmaskActive(s sys.System) bool {
	for _, l := range strings.Split(sys.ReadString(s, CommonSession), "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "#") && strings.Contains(l, "pam_umask.so") {
			return true
		}
	}
	return false
}

// OptionalGroups can be offered in the form.
var OptionalGroups = []string{"docker", "adm", "systemd-journal"}

// Module is the users module.
type Module struct {
	created bool
}

// New returns the users module.
func New() *Module { return &Module{} }

func (*Module) ID() string   { return "users" }
func (*Module) Name() string { return "Users and sudo" }
func (*Module) Description() string {
	return "admin user with sudo, locked root password, safe permissions, umask 027"
}

func (m *Module) Form(env *module.Env) []*huh.Group {
	a := &env.Answers.Users
	var groupOpts []huh.Option[string]
	for _, g := range OptionalGroups {
		groupOpts = append(groupOpts, huh.NewOption(g, g).Selected(slices.Contains(a.ExtraGroups, g)))
	}
	return []*huh.Group{
		huh.NewGroup(
			huh.NewConfirm().
				Title("Create an admin user?").
				Description("Recommended: log in as a normal user and use sudo. No = keep root as the only admin (key-only login).").
				Value(&a.CreateAdmin),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("Admin user name").
				Description("Created without a password for SSH (keys only). An existing user is reused.").
				Value(&a.Name).
				Validate(func(s string) error {
					if !sys.UserNameRe.MatchString(s) || s == "root" {
						return errors.New("use a valid Linux user name other than root")
					}
					return nil
				}),
			huh.NewConfirm().
				Title("sudo without password (NOPASSWD)?").
				Description("Yes: convenient, the SSH key is the only secret. No: sudo asks for a password, which you set now.").
				Value(&a.SudoNoPassword),
		).WithHideFunc(func() bool { return !a.CreateAdmin }),
		huh.NewGroup(
			huh.NewInput().
				Title("Password for sudo").
				Description("At least 8 characters. Leave empty to keep the password the user already has.").
				EchoMode(huh.EchoModePassword).
				Value(&a.Password).
				Validate(func(s string) error {
					if s != "" && len(s) < 8 {
						return errors.New("at least 8 characters")
					}
					return nil
				}),
		).WithHideFunc(func() bool { return !a.CreateAdmin || a.SudoNoPassword }),
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Extra groups for the admin").
				Description("docker = manage containers (root-equivalent), adm/systemd-journal = read logs. Missing groups are skipped.").
				Options(groupOpts...).
				Value(&a.ExtraGroups).
				Height(len(groupOpts) + 4),
		).WithHideFunc(env.Advanced(func() bool { return !a.CreateAdmin })),
		huh.NewGroup(
			huh.NewConfirm().
				Title("Lock the root password?").
				Description("Root can then not log in with a password anywhere (also not on the provider's web console). SSH keys keep working.").
				Value(&a.LockRoot),
			huh.NewConfirm().
				Title("Set umask 027?").
				Description("New files are not readable by other users (UMASK in /etc/login.defs, applied by pam_umask).").
				Value(&a.Umask027),
		).WithHideFunc(env.Advanced(nil)),
	}
}

type host struct {
	adminExists bool
	adminHome   string
	adminGroups []string
	adminPass   string // P, L, NP
	adminGecos  string
	rootPass    string
	emptyPass   []string
}

func passwdStatus(ctx context.Context, s sys.System, user string) string {
	out, err := s.Query(ctx, "passwd", "-S", user)
	if err != nil {
		return ""
	}
	if f := strings.Fields(out); len(f) >= 2 {
		return f[1]
	}
	return ""
}

func gecos(ctx context.Context, s sys.System, user string) string {
	out, err := s.Query(ctx, "getent", "passwd", user)
	if err != nil {
		return ""
	}
	if f := strings.Split(strings.TrimSpace(out), ":"); len(f) >= 5 {
		// adduser writes ",,," for "no information"
		return strings.Trim(f[4], ",")
	}
	return ""
}

// EmptyPasswords lists accounts whose shadow password field is empty (they
// could log in without a password where PAM allows it).
func EmptyPasswords(shadow string) []string {
	var users []string
	for _, l := range strings.Split(shadow, "\n") {
		f := strings.Split(l, ":")
		if len(f) >= 2 && f[0] != "" && f[1] == "" {
			users = append(users, f[0])
		}
	}
	return users
}

func readHost(ctx context.Context, env *module.Env) host {
	a := env.Answers.Users
	var h host
	if pw, ok := sys.LookupUser(ctx, env.Sys, a.Name); ok && a.CreateAdmin {
		h.adminExists = true
		h.adminHome = pw.Home
		h.adminGroups = sys.UserGroups(ctx, env.Sys, a.Name)
		h.adminPass = passwdStatus(ctx, env.Sys, a.Name)
		h.adminGecos = gecos(ctx, env.Sys, a.Name)
	}
	h.rootPass = passwdStatus(ctx, env.Sys, "root")
	h.emptyPass = EmptyPasswords(sys.ReadString(env.Sys, "/etc/shadow"))
	return h
}

// SetUmask sets UMASK in login.defs content.
func SetUmask(content, value string) string {
	lines := strings.Split(content, "\n")
	for i, l := range lines {
		if f := strings.Fields(l); len(f) >= 1 && f[0] == "UMASK" {
			lines[i] = "UMASK\t\t" + value
			return strings.Join(lines, "\n")
		}
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + "UMASK\t\t" + value + "\n"
}

func umaskOf(content string) string {
	for _, l := range strings.Split(content, "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "UMASK" {
			return f[1]
		}
	}
	return ""
}

func (m *Module) wantGroups(ctx context.Context, env *module.Env) (add, missing []string) {
	a := env.Answers.Users
	for _, g := range append([]string{"sudo"}, a.ExtraGroups...) {
		if !sys.GroupExists(ctx, env.Sys, g) {
			missing = append(missing, g)
			continue
		}
		add = append(add, g)
	}
	return add, missing
}

func (m *Module) Check(ctx context.Context, env *module.Env) (module.Plan, error) {
	var p module.Plan
	a := env.Answers.Users
	h := readHost(ctx, env)
	if a.CreateAdmin {
		if !sys.UserNameRe.MatchString(a.Name) || a.Name == "root" {
			return p, fmt.Errorf("users.name %q is not a valid user name", a.Name)
		}
		if !h.adminExists {
			p.Add(module.KindUser, a.Name, "create user %s (shell /bin/bash, no password for SSH)", a.Name)
		}
		add, missing := m.wantGroups(ctx, env)
		for _, g := range add {
			if !slices.Contains(h.adminGroups, g) {
				p.Add(module.KindUser, a.Name, "add %s to group %s", a.Name, g)
			}
		}
		for _, g := range missing {
			p.Note("group %s does not exist (yet), %s is not added to it", g, a.Name)
		}
		p.PlanFile(env.Sys, shared.SudoersFile(a.Name), shared.RenderSudoers(a.Name, a.SudoNoPassword), 0o440,
			"sudo for "+a.Name+" ("+map[bool]string{true: "NOPASSWD", false: "with password"}[a.SudoNoPassword]+")")
		if !a.SudoNoPassword {
			switch {
			case a.Password != "" || a.PasswordHash != "":
				if h.adminPass != "P" {
					p.Add(module.KindUser, a.Name, "set the password of %s", a.Name)
				}
			case h.adminPass != "P":
				return p, fmt.Errorf("sudo with password needs a password for %s (users.password_hash or the form)", a.Name)
			}
		}
		if a.Umask027 && !strings.Contains(h.adminGecos, "umask=027") && (h.adminGecos == "" || !h.adminExists) {
			p.Add(module.KindUser, a.Name, "umask 027 for %s (GECOS umask=027, read by pam_umask)", a.Name)
		}
		if h.adminExists {
			m.planPerms(env, &p, h.adminHome)
		}
	}
	m.planPerms(env, &p, "/root")
	if a.LockRoot && h.rootPass != "L" {
		p.Risky(module.KindUser, "root", "lock the root password (key login keeps working)")
	}
	for _, u := range h.emptyPass {
		p.Risky(module.KindUser, u, "lock account %s: it has an EMPTY password", u)
	}
	if a.Umask027 && umaskOf(sys.ReadString(env.Sys, LoginDefs)) != "027" {
		p.Add(module.KindFile, LoginDefs, "UMASK 027 in %s", LoginDefs)
	}
	if a.Umask027 && !pamUmaskActive(env.Sys) {
		p.Add(module.KindFile, UmaskProfile, "enable pam_umask for all sessions (pam-auth-update profile %s)", UmaskProfile)
	}
	return p, nil
}

// planPerms checks the home and ~/.ssh permissions sshd (StrictModes)
// requires.
func (m *Module) planPerms(env *module.Env, p *module.Plan, home string) {
	for _, c := range permChanges(env.Sys, home) {
		p.Add(module.KindFile, c.path, "chmod %04o %s", c.mode, c.path)
	}
}

type permChange struct {
	path string
	mode fs.FileMode
}

func permChanges(s sys.System, home string) []permChange {
	var out []permChange
	if st, err := s.Stat(home); err == nil && st.Mode().Perm()&0o022 != 0 {
		out = append(out, permChange{home, st.Mode().Perm() &^ 0o022})
	}
	sshDir := path.Join(home, ".ssh")
	if st, err := s.Stat(sshDir); err == nil && st.Mode().Perm() != 0o700 {
		out = append(out, permChange{sshDir, 0o700})
	}
	ak := path.Join(sshDir, "authorized_keys")
	if st, err := s.Stat(ak); err == nil && st.Mode().Perm() != 0o600 {
		out = append(out, permChange{ak, 0o600})
	}
	return out
}

func (m *Module) Apply(ctx context.Context, env *module.Env, _ module.Plan) error {
	a := env.Answers.Users
	h := readHost(ctx, env)
	if a.CreateAdmin {
		if !h.adminExists {
			if _, err := env.Exec(ctx, "adduser", "--disabled-password", "--gecos", "", "--shell", "/bin/bash", a.Name); err != nil {
				return err
			}
			m.created = true
			env.Infof("created user %s", a.Name)
			h = readHost(ctx, env)
		}
		// pam_umask reads umask= from GECOS; it overrides the user-private-
		// group rule that would turn UMASK 027 into 007 for this user.
		// (adduser --gecos refuses '=', usermod -c does not.)
		if a.Umask027 && h.adminGecos == "" {
			if _, err := env.Exec(ctx, "usermod", "-c", "umask=027", a.Name); err != nil {
				return err
			}
			if !m.created {
				if err := env.Undo("clear GECOS", "usermod", "-c", "", a.Name); err != nil {
					return err
				}
			}
		}
		add, _ := m.wantGroups(ctx, env)
		for _, g := range add {
			if slices.Contains(h.adminGroups, g) {
				continue
			}
			if _, err := env.Exec(ctx, "usermod", "-aG", g, a.Name); err != nil {
				return err
			}
			if err := env.Undo("leave group "+g, "gpasswd", "-d", a.Name, g); err != nil {
				return err
			}
			env.Infof("added %s to group %s", a.Name, g)
		}
		if !a.SudoNoPassword && h.adminPass != "P" {
			c := sys.Cmd{Name: "chpasswd", Stdin: a.Name + ":" + a.Password + "\n"}
			if a.Password == "" {
				c = sys.Cmd{Name: "chpasswd", Args: []string{"-e"}, Stdin: a.Name + ":" + a.PasswordHash + "\n"}
			}
			if _, err := env.Sys.Run(ctx, c); err != nil {
				return fmt.Errorf("setting the password of %s failed: %w", a.Name, err)
			}
			env.Infof("password of %s set", a.Name)
		}
		if _, err := shared.WriteSudoers(ctx, env, a.Name, a.SudoNoPassword); err != nil {
			return err
		}
		if err := fixPerms(env, h.adminHome); err != nil {
			return err
		}
	}
	if err := fixPerms(env, "/root"); err != nil {
		return err
	}
	if a.LockRoot && h.rootPass != "L" {
		if _, err := env.Exec(ctx, "passwd", "-l", "root"); err != nil {
			return err
		}
		if err := env.Undo("unlock root password", "passwd", "-u", "root"); err != nil {
			return err
		}
		env.Infof("root password locked")
	}
	for _, u := range h.emptyPass {
		if _, err := env.Exec(ctx, "passwd", "-l", u); err != nil {
			return err
		}
		env.Warnf("locked %s: it had an empty password", u)
	}
	if a.Umask027 {
		if _, err := env.EditFile(LoginDefs, 0o644, func(old string) string { return SetUmask(old, "027") }); err != nil {
			return err
		}
		if !pamUmaskActive(env.Sys) {
			if _, err := env.PutFile(UmaskProfile, RenderUmaskProfile(), 0o644); err != nil {
				return err
			}
			if _, err := env.Exec(ctx, "pam-auth-update", "--package"); err != nil {
				return err
			}
			// replayed before the profile file is removed
			if err := env.Undo("disable pam_umask", "pam-auth-update", "--package", "--remove", umaskProfileID); err != nil {
				return err
			}
			env.Infof("pam_umask enabled for all sessions")
		}
	}
	return nil
}

func fixPerms(env *module.Env, home string) error {
	if home == "" {
		return nil
	}
	for _, c := range permChanges(env.Sys, home) {
		if err := env.Sys.Chmod(c.path, c.mode); err != nil {
			return err
		}
		env.Infof("chmod %04o %s", c.mode, c.path)
	}
	return nil
}

// Rollback undoes groups, sudo, root lock and umask. A created user is
// kept: SSH may be configured to log in only as that user.
func (m *Module) Rollback(ctx context.Context, env *module.Env) error {
	return env.Rollback(ctx)
}

func (m *Module) Report(env *module.Env) []module.ReportLine {
	a := env.Answers.Users
	if !a.CreateAdmin {
		return []module.ReportLine{{Label: "Admin", Value: "root (key-only login)"}}
	}
	sudo := "sudo without password"
	if !a.SudoNoPassword {
		sudo = "sudo with password"
	}
	return []module.ReportLine{{Label: "Admin", Value: fmt.Sprintf("%s, %s", a.Name, sudo)}}
}
