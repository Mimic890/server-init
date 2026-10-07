package ssh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/modules/shared"
	"github.com/mimic890/server-init/internal/state"
	"github.com/mimic890/server-init/internal/sys"
)

// ConfirmTimeout is how long the admin has to confirm the new login before
// the watchdog rolls back (same as ssh-setup.sh).
const ConfirmTimeout = 180 * time.Second

// pollInterval is how often the port is checked after a restart.
var pollInterval = time.Second

// pending is stored when the old port stays open until `ssh finalize`.
type pending struct {
	Port     int    `json:"port"`
	OldPorts []int  `json:"old_ports"`
	Config   string `json:"config"`
	Socket   string `json:"socket,omitempty"`
}

func (m *Module) Apply(ctx context.Context, env *module.Env, _ module.Plan) error {
	s, err := m.resolve(ctx, env)
	if err != nil {
		return err
	}
	a := env.Answers.SSH
	m.res = result{oldPorts: s.oldPorts, fw: s.fw}

	if !sys.Has(env.Sys, "sshd") {
		if err := sys.AptUpdate(ctx, env.Sys); err != nil {
			return err
		}
		if err := env.Install(ctx, "openssh-server"); err != nil {
			return err
		}
	}

	// Everything the watchdog must be able to restore, saved as it is now.
	others, _ := env.Sys.Glob("/etc/ssh/sshd_config.d/*.conf")
	neutralize := []string{}
	for _, f := range append([]string{"/etc/ssh/sshd_config"}, others...) {
		if f == DropIn || slices.Contains(legacyFiles, f) {
			continue
		}
		if _, changed := NeutralizePorts(sys.ReadString(env.Sys, f)); changed {
			neutralize = append(neutralize, f)
		}
	}
	tracked := append(append([]string{DropIn, SocketDropIn}, legacyFiles...), neutralize...)
	steps, err := m.restoreSteps(env, tracked)
	if err != nil {
		return err
	}
	if err := env.Sys.WriteFile(RollbackScript, []byte(RenderRollback(steps)), 0o700); err != nil {
		return err
	}
	rollbackNow := func(reason string) error {
		env.Warnf("rolling back the SSH configuration")
		if _, err := env.Exec(ctx, "bash", RollbackScript); err != nil {
			env.Warnf("rollback script failed: %v", err)
		}
		stopWatchdog(ctx, env)
		return errors.New(reason)
	}

	for _, f := range legacyFiles {
		if ok, err := env.RemoveFile(f); err != nil {
			return err
		} else if ok {
			env.Infof("removed %s (ssh-setup.sh)", f)
		}
	}
	for _, f := range neutralize {
		if _, err := env.EditFile(f, 0o644, func(old string) string { s, _ := NeutralizePorts(old); return s }); err != nil {
			return err
		}
		env.Warnf("commented out an active Port line in %s (backup kept)", f)
	}
	if !sys.Exists(env.Sys, HostKey) {
		if _, err := env.Exec(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", HostKey); err != nil {
			return err
		}
		for _, f := range []string{HostKey, HostKey + ".pub"} {
			if err := env.Journal.Add(state.Entry{Op: state.OpCreate, Path: f}); err != nil {
				return err
			}
		}
		env.Infof("generated the missing ed25519 host key")
	}
	if a.Banner != "" {
		if _, err := env.PutFile(BannerFile, a.Banner+"\n", 0o644); err != nil {
			return err
		}
	}
	if s.create {
		if err := shared.CreateUser(ctx, env, s.user, "", false); err != nil {
			return err
		}
		if a.GrantSudo {
			if _, err := shared.WriteSudoers(ctx, env, s.user, true); err != nil {
				return err
			}
			env.Infof("granted passwordless sudo to %s", s.user)
		}
		if pw, ok := sys.LookupUser(ctx, env.Sys, s.user); ok {
			s.home = pw.Home
			s.genKeyPath = path.Join(s.home, ".ssh", "server-init_ed25519")
		}
	}
	if err := m.installKey(ctx, env, &s); err != nil {
		return err
	}

	// Phase 1: listen on the old AND the new port, so nothing can lock you out.
	phase1 := slices.Clone(s.oldPorts)
	if !slices.Contains(phase1, s.port) {
		phase1 = append(phase1, s.port)
	}
	params := s.params
	params.Ports = phase1
	if _, err := env.PutFile(DropIn, RenderConfig(params), 0o644); err != nil {
		return err
	}
	_ = env.Sys.MkdirAll("/run/sshd", 0o755) // sshd -t needs it with socket activation
	if _, err := env.Exec(ctx, "sshd", "-t"); err != nil {
		return rollbackNow(fmt.Sprintf("sshd rejected the new configuration, nothing was changed: %v", err))
	}
	if err := verifyEffective(ctx, env, s.user); err != nil {
		return rollbackNow(err.Error())
	}
	env.Infof("configuration is valid (sshd -t, sshd -T)")

	portChanged := !slices.Equal(s.oldPorts, []int{s.port})
	if portChanged {
		switch {
		case s.fw == fwUFW && env.Selected("ufw"), (s.fw == fwUFW || s.fw == fwFirewalld) && a.OpenFirewall:
			if err := openPort(ctx, env, s.fw, s.port, true); err != nil {
				return rollbackNow(fmt.Sprintf("could not open the port in %s: %v", s.fw, err))
			}
			m.res.fwOpened = true
		}
	}
	if env.Facts.SSHSocket {
		if _, err := env.PutFile(SocketDropIn, RenderSocket(phase1), 0o644); err != nil {
			return rollbackNow(err.Error())
		}
	}

	deadline := time.Now().Add(ConfirmTimeout)
	startWatchdog(ctx, env)
	if err := restartSSHD(ctx, env); err != nil {
		return rollbackNow(fmt.Sprintf("restarting sshd failed: %v", err))
	}
	if !waitListening(ctx, env.Sys, s.port) {
		return rollbackNow(fmt.Sprintf("sshd is not listening on port %d", s.port))
	}
	env.Infof("sshd is listening on port(s) %v", phase1)

	host := env.Facts.ServerIP
	if host == "" {
		host = "<server-ip>"
	}
	keyOpt := ""
	if a.KeyMode == "generate" {
		keyOpt = "-i <private-key> "
	}
	m.res.loginTarget = fmt.Sprintf("ssh -p %d %s%s@%s", s.port, keyOpt, s.user, host)

	confirmed, err := m.confirm(ctx, env, s, deadline)
	if err != nil {
		return rollbackNow(err.Error())
	}
	m.res.applied = true
	if !confirmed {
		// Non-interactive and the login could not be proven: keep both ports.
		stopWatchdog(ctx, env)
		final := pending{Port: s.port, OldPorts: s.oldPorts, Config: RenderConfig(s.params)}
		if env.Facts.SSHSocket {
			final.Socket = RenderSocket([]int{s.port})
		}
		b, _ := json.MarshalIndent(final, "", "  ")
		if err := env.Sys.WriteFile(PendingFile, b, 0o600); err != nil {
			return err
		}
		m.res.pending = portChanged
		env.Warnf("login on port %d not verified automatically: old port(s) %v stay open until `server-init ssh finalize`", s.port, s.oldPorts)
		return nil
	}
	stopWatchdog(ctx, env)
	m.res.confirmed = true
	env.Infof("login confirmed, automatic rollback cancelled")

	if portChanged {
		if err := finalizePorts(ctx, env, s.port, RenderConfig(s.params), socketFor(env, s.port)); err != nil {
			return err
		}
	}
	_ = env.Sys.Remove(PendingFile)
	return m.handlePrivateKey(ctx, env, s)
}

func socketFor(env *module.Env, port int) string {
	if !env.Facts.SSHSocket {
		return ""
	}
	return RenderSocket([]int{port})
}

// restoreSteps backs up the tracked files as they are right now, so the
// watchdog restores the state before THIS run.
func (m *Module) restoreSteps(env *module.Env, paths []string) ([]RestoreStep, error) {
	var steps []RestoreStep
	for _, p := range paths {
		if !sys.Exists(env.Sys, p) {
			steps = append(steps, RestoreStep{Path: p})
			continue
		}
		b, err := env.Run.BackupFile(p)
		if err != nil {
			return nil, err
		}
		steps = append(steps, RestoreStep{Path: p, Backup: b})
	}
	return steps, nil
}

func (m *Module) installKey(ctx context.Context, env *module.Env, s *settings) error {
	grp := sys.PrimaryGroup(ctx, env.Sys, s.user)
	sshDir := path.Join(s.home, ".ssh")
	ak := path.Join(sshDir, "authorized_keys")
	if err := env.Sys.MkdirAll(sshDir, 0o700); err != nil {
		return err
	}
	if err := env.Sys.Chown(sshDir, s.user, grp); err != nil {
		return err
	}
	if sys.Exists(env.Sys, ak) {
		if _, err := env.Run.BackupFile(ak); err != nil {
			return err
		}
	}
	if s.generate {
		args := []string{"-q", "-t", "ed25519", "-a", "100",
			"-C", fmt.Sprintf("%s@%s-%s", s.user, env.Facts.Hostname, time.Now().Format("2006-01-02")),
			"-f", s.genKeyPath, "-N", m.passphrase}
		if _, err := env.Exec(ctx, "ssh-keygen", args...); err != nil {
			return err
		}
		for f, mode := range map[string]fs.FileMode{s.genKeyPath: 0o600, s.genKeyPath + ".pub": 0o644} {
			if err := env.Sys.Chown(f, s.user, grp); err != nil {
				return err
			}
			if err := env.Sys.Chmod(f, mode); err != nil {
				return err
			}
		}
		s.pubKey = strings.TrimSpace(sys.ReadString(env.Sys, s.genKeyPath+".pub"))
		env.Infof("generated key pair %s", s.genKeyPath)
	}
	if s.genKeyPath != "" && sys.Exists(env.Sys, s.genKeyPath) {
		m.res.keyPath = s.genKeyPath
	}
	// authorized_keys is not journaled: like ssh-setup.sh, a rollback keeps
	// the added key (other keys already in the file are kept too).
	cur := sys.ReadString(env.Sys, ak)
	if !shared.HasKey(cur, s.pubKey) {
		if cur != "" && !strings.HasSuffix(cur, "\n") {
			cur += "\n"
		}
		if err := env.Sys.WriteFile(ak, []byte(cur+s.pubKey+"\n"), 0o600); err != nil {
			return err
		}
		env.Infof("public key installed in %s", ak)
	}
	if err := env.Sys.Chown(ak, s.user, grp); err != nil {
		return err
	}
	if err := env.Sys.Chmod(ak, 0o600); err != nil {
		return err
	}
	// sshd (StrictModes) ignores keys when the home is writable by others.
	if st, err := env.Sys.Stat(s.home); err == nil && st.Mode().Perm()&0o022 != 0 {
		return env.Sys.Chmod(s.home, st.Mode().Perm()&^0o022)
	}
	return nil
}

// verifyEffective checks with sshd -T that passwords are really off (another
// config could override the drop-in).
func verifyEffective(ctx context.Context, env *module.Env, user string) error {
	out, err := env.Sys.Query(ctx, "sshd", "-T", "-C", "user="+user+",host=localhost,addr=127.0.0.1")
	if err != nil {
		return fmt.Errorf("sshd -T failed: %w", err)
	}
	lines := strings.Split(strings.ToLower(out), "\n")
	if !slices.Contains(lines, "passwordauthentication no") {
		return errors.New("sshd still allows password authentication (another config overrides server-init)")
	}
	if !slices.Contains(lines, "kbdinteractiveauthentication no") {
		return errors.New("sshd still allows keyboard-interactive authentication")
	}
	return nil
}

func startWatchdog(ctx context.Context, env *module.Env) {
	stopWatchdog(ctx, env)
	// AccuracySec: the default of one minute would let the timer fire late.
	_, err := env.Exec(ctx, "systemd-run", "--quiet", "--unit="+WatchdogUnit,
		fmt.Sprintf("--on-active=%ds", int(ConfirmTimeout.Seconds())), "--timer-property=AccuracySec=1s",
		"/bin/bash", RollbackScript)
	if err != nil {
		env.Warnf("could not schedule the automatic rollback timer: %v", err)
		return
	}
	env.Infof("automatic rollback armed: %s.timer fires in %s", WatchdogUnit, ConfirmTimeout)
}

func stopWatchdog(ctx context.Context, env *module.Env) {
	_, _ = env.Sys.Run(ctx, sys.Command("systemctl", "stop", WatchdogUnit+".timer"))
	_, _ = env.Sys.Run(ctx, sys.Command("systemctl", "reset-failed", WatchdogUnit+".timer", WatchdogUnit+".service"))
}

func restartSSHD(ctx context.Context, env *module.Env) error {
	if err := sys.DaemonReload(ctx, env.Sys); err != nil {
		return err
	}
	// Several restarts in a few seconds (apply, then a quick rollback) hit
	// systemd's start limit; reset it first.
	_, _ = env.Sys.Run(ctx, sys.Command("systemctl", "reset-failed", "ssh.service", "ssh.socket"))
	if env.Facts.SSHSocket {
		if err := sys.Systemctl(ctx, env.Sys, "restart", "ssh.socket"); err != nil {
			return err
		}
		return sys.Systemctl(ctx, env.Sys, "restart", "ssh.service")
	}
	if err := sys.Systemctl(ctx, env.Sys, "restart", "ssh.service"); err != nil {
		return sys.Systemctl(ctx, env.Sys, "restart", "sshd.service")
	}
	return nil
}

func waitListening(ctx context.Context, s sys.System, port int) bool {
	for range 10 {
		if sys.PortListening(ctx, s, port) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(pollInterval):
		}
	}
	return false
}

// confirm asks the user to log in from a second terminal (interactive) or
// verifies the login itself (--config). It returns false without error when
// the login cannot be verified automatically.
func (m *Module) confirm(ctx context.Context, env *module.Env, s settings, deadline time.Time) (bool, error) {
	a := env.Answers.SSH
	if env.Prompt.Interactive() {
		c := module.LoginCheck{
			Command: m.res.loginTarget,
			Timeout: time.Until(deadline) - 5*time.Second,
		}
		if a.KeyMode == "generate" && s.generate {
			if a.KeyKeep == "show" {
				c.PrivateKey = sys.ReadString(env.Sys, s.genKeyPath)
			} else {
				c.KeyPath = s.genKeyPath
			}
		}
		ok, err := env.Prompt.ConfirmLogin(ctx, c)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, errors.New("new login not confirmed - SSH configuration was rolled back, nothing else was changed")
		}
		return true, nil
	}
	// Automatic check: a key generated here without passphrase can prove the
	// login end to end.
	if s.genKeyPath != "" && !a.Passphrase && sys.Exists(env.Sys, s.genKeyPath) {
		_, err := env.Sys.Query(ctx, "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=10",
			"-i", s.genKeyPath, "-p", fmt.Sprint(s.port), s.user+"@127.0.0.1", "true")
		if err != nil {
			return false, fmt.Errorf("automatic login test on port %d failed: %w", s.port, err)
		}
		env.Infof("automatic login test on port %d succeeded", s.port)
		return true, nil
	}
	if slices.Equal(s.oldPorts, []int{s.port}) {
		return true, nil // nothing to close
	}
	return false, nil
}

// finalizePorts closes the old ports: the drop-in gets only the new port.
func finalizePorts(ctx context.Context, env *module.Env, port int, config, socket string) error {
	prev := sys.ReadString(env.Sys, DropIn)
	if _, err := env.PutFile(DropIn, config, 0o644); err != nil {
		return err
	}
	if _, err := env.Exec(ctx, "sshd", "-t"); err != nil {
		_ = env.Sys.WriteFile(DropIn, []byte(prev), 0o644)
		return fmt.Errorf("final configuration invalid, kept both ports: %w", err)
	}
	if socket != "" {
		if _, err := env.PutFile(SocketDropIn, socket, 0o644); err != nil {
			return err
		}
	}
	if err := restartSSHD(ctx, env); err != nil {
		return err
	}
	if !waitListening(ctx, env.Sys, port) {
		return fmt.Errorf("sshd is not listening on %d after the final restart! Run: server-init --rollback ssh", port)
	}
	env.Infof("sshd now listens only on port %d", port)
	for _, fn := range OnFinalize {
		if err := fn(ctx, env, port); err != nil {
			env.Warnf("%v", err)
		}
	}
	return nil
}

// OnFinalize hooks run after the old SSH ports were closed (the ufw module
// removes its rules for them).
var OnFinalize []func(ctx context.Context, env *module.Env, port int) error

func (m *Module) handlePrivateKey(ctx context.Context, env *module.Env, s settings) error {
	a := env.Answers.SSH
	if !s.generate || a.KeyKeep != "show" || m.res.keyPath == "" {
		return nil
	}
	if !env.Prompt.Interactive() {
		env.Warnf("private key kept at %s (it can only be shown in the interactive mode)", m.res.keyPath)
		return nil
	}
	del, err := env.Prompt.Confirm(ctx, "Have you saved the private key? Delete it from the server now? (the public key stays in authorized_keys)", true)
	if err != nil || !del {
		env.Warnf("private key kept at %s", m.res.keyPath)
		return nil //nolint:nilerr // keeping the key is a valid answer
	}
	if _, err := env.Exec(ctx, "shred", "-u", m.res.keyPath); err != nil {
		if err := env.Sys.Remove(m.res.keyPath); err != nil {
			return err
		}
	}
	m.res.keyDeleted = true
	env.Infof("private key deleted from the server")
	return nil
}

// Rollback restores the SSH configuration from before server-init (the
// added public key and created users are kept, as in ssh-setup.sh).
func (m *Module) Rollback(ctx context.Context, env *module.Env) error {
	stopWatchdog(ctx, env)
	err := env.Rollback(ctx)
	_ = env.Sys.Remove(PendingFile)
	// The firewall may only allow the new port by now: open the restored
	// port(s) first, or the rollback itself would lock the user out.
	if fw := detectFirewall(ctx, env.Sys); fw == fwUFW || fw == fwFirewalld {
		for _, p := range configuredPorts(ctx, env.Sys) {
			if oerr := openPort(ctx, env, fw, p, false); oerr != nil {
				err = errors.Join(err, oerr)
			}
		}
	}
	if rerr := restartSSHD(ctx, env); rerr != nil {
		err = errors.Join(err, rerr)
	}
	return err
}

// configuredPorts returns the ports of the sshd configuration on disk.
func configuredPorts(ctx context.Context, s sys.System) []int {
	out, err := s.Query(ctx, "sshd", "-T")
	if err != nil {
		return []int{22}
	}
	var ports []int
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[0] == "port" {
			var p int
			if _, err := fmt.Sscan(f[1], &p); err == nil && !slices.Contains(ports, p) {
				ports = append(ports, p)
			}
		}
	}
	if len(ports) == 0 {
		return []int{22}
	}
	return ports
}
