// Package modules lists all modules in apply order.
package modules

import (
	"context"
	"io"

	"github.com/mimic890/server-init/internal/audit"
	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/modules/cleanup"
	"github.com/mimic890/server-init/internal/modules/fail2ban"
	"github.com/mimic890/server-init/internal/modules/preflight"
	"github.com/mimic890/server-init/internal/modules/ssh"
	"github.com/mimic890/server-init/internal/modules/sysctl"
	"github.com/mimic890/server-init/internal/modules/system"
	"github.com/mimic890/server-init/internal/modules/ufw"
	"github.com/mimic890/server-init/internal/modules/users"
	"github.com/mimic890/server-init/internal/scan"
)

// Registry returns every module in apply order.
func Registry() *module.Registry {
	return module.NewRegistry(
		preflight.New(),
		system.New(),
		cleanup.New(),
		users.New(),
		ssh.New(),
		ufw.New(),
		fail2ban.New(),
		sysctl.New(),
	)
}

// Command is a `server-init <name> ...` subcommand.
type Command = func(ctx context.Context, env *module.Env, args []string, out io.Writer) error

// Commands returns the subcommands provided by modules.
func Commands() map[string]Command {
	return map[string]Command{
		"ssh":   ssh.Command,
		"f2b":   fail2ban.Command,
		"audit": audit.Command,
		"scan":  scan.Command,
	}
}
