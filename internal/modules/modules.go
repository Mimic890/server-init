// Package modules lists all modules in apply order.
package modules

import (
	"context"
	"io"

	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/modules/preflight"
	"github.com/mimic890/server-init/internal/modules/ssh"
)

// Registry returns every module in apply order.
func Registry() *module.Registry {
	return module.NewRegistry(
		preflight.New(),
		ssh.New(),
	)
}

// Command is a `server-init <name> ...` subcommand.
type Command func(ctx context.Context, env *module.Env, args []string, out io.Writer) error

// Commands returns the subcommands provided by modules.
func Commands() map[string]Command {
	return map[string]Command{
		"ssh": ssh.Command,
	}
}
