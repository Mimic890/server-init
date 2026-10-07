package ssh

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"charm.land/huh/v2"

	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/modules/shared"
	"github.com/mimic890/server-init/internal/sys"
)

// formState holds the text inputs that are converted into answers.
type formState struct {
	port, maxTries, grace string
	lowPortOK             bool
	banner                bool
}

// Form asks the questions of ssh-setup.sh (firewall and fail2ban questions
// live in their own modules).
func (m *Module) Form(env *module.Env) []*huh.Group {
	a := &env.Answers.SSH
	ctx := context.Background()
	st := &formState{
		port:     strconv.Itoa(a.Port),
		maxTries: strconv.Itoa(a.MaxAuthTries),
		grace:    strconv.Itoa(a.LoginGraceTime),
		banner:   a.Banner != "",
	}
	if a.Banner == "" {
		a.Banner = "Authorized access only. All activity may be logged."
	}
	if env.Quick {
		// the login user follows the users module (resolved at Check)
		a.User = ""
	}
	oldPorts := env.Facts.SSHPorts
	userExists := func() bool { _, ok := sys.LookupUser(ctx, env.Sys, a.User); return ok }

	groups := []*huh.Group{
		huh.NewGroup(
			huh.NewInput().
				Title("SSH port").
				Description("Bots scan port 22 all day. Another port removes most of the noise (keys + fail2ban do the real work). Suggested: a random free port.").
				Value(&st.port).
				Validate(func(s string) error {
					p, err := strconv.Atoi(strings.TrimSpace(s))
					if err != nil || p < 1 || p > 65535 {
						return errors.New("enter a number from 1 to 65535")
					}
					if !slices.Contains(oldPorts, p) && sys.PortListening(ctx, env.Sys, p) {
						return fmt.Errorf("port %d is already in use by another program", p)
					}
					a.Port = p
					return nil
				}),
		),
		huh.NewGroup(
			huh.NewConfirm().
				TitleFunc(func() string { return fmt.Sprintf("Use port %d anyway?", a.Port) }, &a.Port).
				Description("Ports below 1024 are reserved for well-known services.").
				Value(&st.lowPortOK).
				Validate(func(ok bool) error {
					if !ok {
						return errors.New("go back with shift+tab and choose another port")
					}
					return nil
				}),
		).WithHideFunc(func() bool { return a.Port >= 1024 || a.Port == 22 || slices.Contains(oldPorts, a.Port) }),
		huh.NewGroup(
			huh.NewInput().
				Title("Login user").
				Description("Account for SSH login. root = key-only root login. Another name is created if missing, and root login over SSH is then disabled.").
				Value(&a.User).
				Validate(func(s string) error {
					if !sys.UserNameRe.MatchString(s) {
						return errors.New("use a valid Linux user name (lowercase letters, digits, _ and -)")
					}
					return nil
				}),
		).WithHideFunc(env.Advanced(nil)),
		huh.NewGroup(
			huh.NewConfirm().
				TitleFunc(func() string { return fmt.Sprintf("Give '%s' sudo rights without password (NOPASSWD)?", a.User) }, &a.User).
				Description("The user is created without a password, so sudo only works without one.").
				Value(&a.GrantSudo),
		).WithHideFunc(env.Advanced(func() bool { return a.User == "root" || usersModuleCreates(env, a.User) || userExists() })),
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("SSH key").
				Description("Passwords are disabled, so you need a key. Only modern ed25519 keys are accepted.").
				Options(
					huh.NewOption("Paste an existing PUBLIC key (from your computer)", "paste"),
					huh.NewOption("Generate a new key pair here on the server", "generate"),
				).
				Value(&a.KeyMode),
		),
		huh.NewGroup(
			huh.NewText().
				Title("Public key").
				Description("One line, e.g.: ssh-ed25519 AAAAC3Nza... comment  (content of ~/.ssh/id_ed25519.pub)").
				Lines(3).
				Value(&a.PublicKey).
				Validate(func(s string) error {
					k, err := shared.ParsePublicKey(s)
					if err == nil {
						a.PublicKey = k
					}
					return err
				}),
		).WithHideFunc(func() bool { return a.KeyMode != "paste" }),
		huh.NewGroup(
			huh.NewConfirm().
				Title("Protect the private key with a passphrase?").
				Description("You will type it on every login (or keep it in your ssh-agent).").
				Value(&a.Passphrase),
		).WithHideFunc(func() bool { return a.KeyMode != "generate" }),
		huh.NewGroup(
			huh.NewInput().
				Title("Passphrase").
				Description("At least 8 characters. Only used to encrypt the key file.").
				EchoMode(huh.EchoModePassword).
				Value(&m.passphrase).
				Validate(func(s string) error {
					if a.Passphrase && len(s) < 8 {
						return errors.New("at least 8 characters")
					}
					return nil
				}),
		).WithHideFunc(func() bool { return a.KeyMode != "generate" || !a.Passphrase }),
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("What to do with the PRIVATE key when everything works?").
				Description("A private key that stays on the server is weaker than one that only lives on your PC.").
				Options(
					huh.NewOption("Show it on screen once, then delete it from the server (safer)", "show"),
					huh.NewOption("Keep it on the server, just show me the path", "keep"),
				).
				Value(&a.KeyKeep),
		).WithHideFunc(func() bool { return a.KeyMode != "generate" }),
		huh.NewGroup(
			huh.NewConfirm().
				TitleFunc(func() string { return fmt.Sprintf("Allow SSH logins only for '%s'?", a.User) }, &a.User).
				Description("AllowUsers: everyone else is refused, even with a valid key. Recommended.").
				Value(&a.AllowOnly),
		).WithHideFunc(env.Advanced(nil)),
		huh.NewGroup(
			huh.NewInput().
				Title("MaxAuthTries").
				Description("Login attempts per connection before it is dropped.").
				Value(&st.maxTries).
				Validate(intIn(1, 99, &a.MaxAuthTries)),
			huh.NewInput().
				Title("LoginGraceTime (seconds)").
				Description("Time a client has to finish logging in.").
				Value(&st.grace).
				Validate(intIn(1, 9999, &a.LoginGraceTime)),
			huh.NewConfirm().
				Title("Enable ClientAlive checks (300s x 2)?").
				Description("Every 5 minutes the server checks the client; after 2 misses the dead session is closed. Idle but alive users stay connected. MaxStartups 10:30:60 is always set.").
				Value(&a.ClientAlive),
		).Title("Brute-force limits").WithHideFunc(env.Advanced(nil)),
		huh.NewGroup(
			huh.NewConfirm().
				Title("Allow X11 forwarding?").
				Description("Remote graphical windows on your PC. Servers rarely need it.").
				Value(&a.X11Forwarding),
			huh.NewSelect[string]().
				Title("AllowTcpForwarding").
				Description("SSH tunnels (ssh -L / -R / -D).").
				Options(
					huh.NewOption("no - no tunnels at all (most secure)", "no"),
					huh.NewOption("local - only 'ssh -L' tunnels from your PC", "local"),
					huh.NewOption("yes - everything allowed", "yes"),
				).
				Value(&a.TCPForwarding),
			huh.NewConfirm().
				Title("Allow agent forwarding?").
				Description("ssh -A: use your local keys to hop further. Risky if the server is compromised.").
				Value(&a.AgentForwarding),
			huh.NewConfirm().
				Title("Set a login banner?").
				Description("Text shown to everyone before login (legal notice). Optional.").
				Value(&st.banner),
		).Title("Forwarding and extras").WithHideFunc(env.Advanced(nil)),
		huh.NewGroup(
			huh.NewInput().
				Title("Banner text (one line)").
				Value(&a.Banner),
		).WithHideFunc(env.Advanced(func() bool { return !st.banner })),
	}
	// Firewall: only asked when a host firewall is active and the ufw module
	// will not take care of the port.
	if fw := detectFirewall(ctx, env.Sys); fw == fwFirewalld || fw == fwUFW && !env.Selected("ufw") {
		groups = append(groups, huh.NewGroup(
			huh.NewConfirm().
				TitleFunc(func() string { return fmt.Sprintf("Open TCP port %d in %s automatically?", a.Port, fw) }, &a.Port).
				Description("If the new port is not opened, you lock yourself out after the port change.").
				Value(&a.OpenFirewall),
		))
	}
	m.form = st
	return groups
}

func intIn(lo, hi int, dst *int) func(string) error {
	return func(s string) error {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || n < lo || n > hi {
			return fmt.Errorf("enter a number from %d to %d", lo, hi)
		}
		*dst = n
		return nil
	}
}
