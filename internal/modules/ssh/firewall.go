package ssh

import (
	"context"
	"fmt"
	"strings"

	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/sys"
)

type firewall string

const (
	fwNone      firewall = ""
	fwUFW       firewall = "ufw"
	fwFirewalld firewall = "firewalld"
	fwOther     firewall = "custom"
)

// detectFirewall works like q_firewall in ssh-setup.sh.
func detectFirewall(ctx context.Context, s sys.System) firewall {
	if sys.Has(s, "ufw") {
		if out, err := s.Query(ctx, "ufw", "status"); err == nil && strings.Contains(out, "Status: active") {
			return fwUFW
		}
	}
	if sys.UnitActive(ctx, s, "firewalld") {
		return fwFirewalld
	}
	if sys.Has(s, "iptables") {
		if out, err := s.Query(ctx, "iptables", "-S", "INPUT"); err == nil &&
			(strings.Contains(out, "-P INPUT DROP") || strings.Contains(out, "-P INPUT REJECT")) {
			return fwOther
		}
	}
	if sys.Has(s, "nft") {
		if out, err := s.Query(ctx, "nft", "list", "ruleset"); err == nil && strings.Contains(out, "policy drop") {
			return fwOther
		}
	}
	return fwNone
}

// openPort opens port in the active ufw/firewalld. With record, the undo
// step is journaled (not during a rollback: a second rollback must never
// close the restored SSH port).
func openPort(ctx context.Context, env *module.Env, fw firewall, port int, record bool) error {
	p := fmt.Sprintf("%d/tcp", port)
	switch fw {
	case fwUFW:
		if _, err := env.Exec(ctx, "ufw", "allow", p, "comment", "SSH (server-init)"); err != nil {
			return err
		}
		env.Infof("ufw: opened %s", p)
		if !record {
			return nil
		}
		return env.Undo("close "+p, "ufw", "delete", "allow", p)
	case fwFirewalld:
		if _, err := env.Exec(ctx, "firewall-cmd", "--permanent", "--add-port="+p); err != nil {
			return err
		}
		if _, err := env.Exec(ctx, "firewall-cmd", "--reload"); err != nil {
			return err
		}
		env.Infof("firewalld: opened %s", p)
		if !record {
			return nil
		}
		return env.Undo("close "+p, "firewall-cmd", "--permanent", "--remove-port="+p)
	}
	return nil
}

func openCmd(fw firewall, port int) string {
	if fw == fwFirewalld {
		return fmt.Sprintf("firewall-cmd --permanent --add-port=%d/tcp && firewall-cmd --reload", port)
	}
	return fmt.Sprintf("ufw allow %d/tcp", port)
}

func closeCmd(fw firewall, ports []int) string {
	var cmds []string
	for _, p := range ports {
		if fw == fwFirewalld {
			cmds = append(cmds, fmt.Sprintf("firewall-cmd --permanent --remove-port=%d/tcp", p))
		} else {
			cmds = append(cmds, fmt.Sprintf("ufw delete allow %d/tcp", p))
		}
	}
	if fw == fwFirewalld {
		cmds = append(cmds, "firewall-cmd --reload")
	}
	return strings.Join(cmds, " && ")
}
