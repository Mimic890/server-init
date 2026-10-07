package sys

import "context"

// UnitActive reports whether a systemd unit is active.
func UnitActive(ctx context.Context, s System, unit string) bool {
	_, err := s.Query(ctx, "systemctl", "is-active", "--quiet", unit)
	return err == nil
}

// UnitEnabled reports whether a systemd unit is enabled.
func UnitEnabled(ctx context.Context, s System, unit string) bool {
	_, err := s.Query(ctx, "systemctl", "is-enabled", "--quiet", unit)
	return err == nil
}

// Systemctl runs systemctl with the given arguments.
func Systemctl(ctx context.Context, s System, args ...string) error {
	_, err := s.Run(ctx, Command("systemctl", args...))
	return err
}

// DaemonReload runs systemctl daemon-reload.
func DaemonReload(ctx context.Context, s System) error {
	return Systemctl(ctx, s, "daemon-reload")
}
