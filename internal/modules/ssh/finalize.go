package ssh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/sys"
)

// Command implements `server-init ssh finalize`: close the old SSH ports
// after a --config run whose login could not be verified automatically.
func Command(ctx context.Context, env *module.Env, args []string, out io.Writer) error {
	if len(args) != 1 || args[0] != "finalize" {
		return errors.New("usage: server-init ssh finalize")
	}
	if !env.Facts.IsRoot {
		return errors.New("run as root")
	}
	b, err := env.Sys.ReadFile(PendingFile)
	if err != nil {
		return errors.New("nothing to finalize: SSH already listens only on its configured port")
	}
	var p pending
	if err := json.Unmarshal(b, &p); err != nil {
		return fmt.Errorf("%s: %w", PendingFile, err)
	}
	if !sys.PortListening(ctx, env.Sys, p.Port) {
		return fmt.Errorf("sshd does not listen on port %d; not closing the old port(s) %v", p.Port, p.OldPorts)
	}
	_, _ = fmt.Fprintf(out, "Closing old SSH port(s) %v, keeping %d.\n", p.OldPorts, p.Port)
	if err := finalizePorts(ctx, env, p.Port, p.Config, p.Socket); err != nil {
		return err
	}
	return env.Sys.Remove(PendingFile)
}
