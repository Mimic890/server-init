package fail2ban

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/state"
	"github.com/mimic890/server-init/internal/sys"
)

const cliUsage = `usage: server-init f2b <command>

  status                 jails, banned IPs, whitelist and blacklist
  unban <ip>             unban one IP
  unban-all              remove all current bans
  whitelist add <ip>     never ban this IP/CIDR
  whitelist del <ip>     remove it from the whitelist
  whitelist list         show the whitelist
  blacklist add <ip>     ban this IP permanently on all ports
  blacklist del <ip>     remove it from the blacklist
  blacklist list         show the blacklist
  sync                   reload fail2ban and re-apply the blacklist`

// Command implements `server-init f2b ...` (the --f2b-* options of
// ssh-setup.sh).
func Command(ctx context.Context, env *module.Env, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		_, _ = fmt.Fprintln(out, cliUsage)
		return nil
	}
	if !env.Facts.IsRoot {
		return errors.New("run as root")
	}
	if !sys.Has(env.Sys, "fail2ban-client") {
		return errors.New("fail2ban is not installed: run server-init with the fail2ban module first")
	}
	s := env.Sys
	say := func(format string, a ...any) { _, _ = fmt.Fprintf(out, format+"\n", a...) }
	arg := func(i int) (string, error) {
		if len(args) <= i {
			return "", errors.New("missing IP address argument")
		}
		if !sys.ValidIPOrCIDR(args[i]) {
			return "", fmt.Errorf("not a valid IP or CIDR: %s", args[i])
		}
		return args[i], nil
	}
	f2b := func(a ...string) (string, error) { return s.Run(ctx, sys.Command("fail2ban-client", a...)) }

	switch args[0] {
	case "status":
		o, err := s.Query(ctx, "fail2ban-client", "status")
		if err != nil {
			return err
		}
		say("%s", o)
		for _, jail := range []string{"sshd", "recidive", BlacklistJail} {
			if o, err := s.Query(ctx, "fail2ban-client", "status", jail); err == nil {
				say("%s", o)
			}
		}
		say("Whitelist (%s):", WhitelistList)
		for _, ip := range ParseList(sys.ReadString(s, WhitelistList)) {
			say("  %s", ip)
		}
		say("Blacklist (%s):", BlacklistList)
		for _, ip := range ParseList(sys.ReadString(s, BlacklistList)) {
			say("  %s", ip)
		}
		return nil
	case "unban-all":
		if _, err := f2b("unban", "--all"); err != nil {
			return err
		}
		say("All current bans were removed.")
		return nil
	case "unban":
		ip, err := arg(1)
		if err != nil {
			return err
		}
		if _, err := f2b("unban", ip); err != nil {
			return err
		}
		say("Unbanned %s", ip)
		return nil
	case "sync":
		if err := reload(ctx, env); err != nil {
			return err
		}
		say("Blacklist re-applied, fail2ban reloaded.")
		return nil
	case "whitelist", "blacklist":
	default:
		return fmt.Errorf("unknown command %q\n\n%s", args[0], cliUsage)
	}

	if len(args) < 2 {
		return errors.New(cliUsage)
	}
	listFile := WhitelistList
	if args[0] == "blacklist" {
		listFile = BlacklistList
	}
	list := ParseList(sys.ReadString(s, listFile))
	if args[1] == "list" {
		for _, ip := range list {
			say("%s", ip)
		}
		return nil
	}
	ip, err := arg(2)
	if err != nil {
		return err
	}
	switch args[1] {
	case "add":
		if !slices.Contains(list, ip) {
			list = append(list, ip)
		}
	case "del":
		list = slices.DeleteFunc(list, func(x string) bool { return x == ip })
	default:
		return fmt.Errorf("unknown %s command %q", args[0], args[1])
	}
	if err := s.MkdirAll(state.ConfDir, 0o700); err != nil {
		return err
	}
	if err := s.WriteFile(listFile, []byte(RenderList(list)), 0o600); err != nil {
		return err
	}

	other := ParseList(sys.ReadString(s, BlacklistList))
	if args[0] == "blacklist" {
		other = ParseList(sys.ReadString(s, WhitelistList))
	}
	switch args[0] + " " + args[1] {
	case "whitelist add", "whitelist del":
		if err := s.WriteFile(WhitelistJail, []byte(RenderWhitelist(list)), 0o644); err != nil {
			return err
		}
		if err := reload(ctx, env); err != nil {
			return err
		}
		if args[1] == "add" {
			_, _ = f2b("unban", ip)
			if slices.Contains(other, ip) {
				say("warning: %s is also in the blacklist - remove it there if unintended.", ip)
			}
			say("Whitelisted %s (never banned by fail2ban)", ip)
		} else {
			say("Removed %s from the whitelist", ip)
		}
	case "blacklist add":
		if _, err := s.Query(ctx, "fail2ban-client", "status", BlacklistJail); err != nil {
			return errors.New("blacklist jail is not active: run server-init with the fail2ban module first")
		}
		if _, err := f2b("set", BlacklistJail, "banip", ip); err != nil {
			return err
		}
		if slices.Contains(other, ip) {
			say("warning: %s is also whitelisted.", ip)
		}
		say("Permanently banned %s on all ports", ip)
	case "blacklist del":
		_, _ = f2b("set", BlacklistJail, "unbanip", ip)
		say("Removed %s from the blacklist", ip)
	}
	return nil
}

func reload(ctx context.Context, env *module.Env) error {
	if _, err := env.Sys.Run(ctx, sys.Command("fail2ban-client", "reload")); err != nil {
		if err := sys.Systemctl(ctx, env.Sys, "restart", "fail2ban"); err != nil {
			return err
		}
	}
	if !waitReady(ctx, env.Sys) {
		return errors.New("fail2ban is not responding")
	}
	syncBlacklist(ctx, env)
	return nil
}
