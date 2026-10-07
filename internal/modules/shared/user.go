// Package shared holds helpers used by more than one module (users and ssh
// both create users and sudoers drop-ins).
package shared

import (
	"context"
	"fmt"
	"path"

	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/sys"
)

// SudoersFile is the drop-in that grants sudo to user.
func SudoersFile(user string) string { return "/etc/sudoers.d/90-server-init-" + user }

// RenderSudoers returns the sudoers drop-in content.
func RenderSudoers(user string, nopasswd bool) string {
	rule := "ALL=(ALL:ALL) ALL"
	if nopasswd {
		rule = "ALL=(ALL:ALL) NOPASSWD:ALL"
	}
	return fmt.Sprintf("# Managed by server-init\n%s %s\n", user, rule)
}

// CreateUser adds a user without a password (key login only). With
// removable the rollback deletes the user again (the home directory is
// kept). Existing users are left alone.
func CreateUser(ctx context.Context, env *module.Env, name, shell string, removable bool) error {
	if _, ok := sys.LookupUser(ctx, env.Sys, name); ok {
		return nil
	}
	args := []string{"--disabled-password", "--gecos", ""}
	if shell != "" {
		args = append(args, "--shell", shell)
	}
	if _, err := env.Exec(ctx, "adduser", append(args, name)...); err != nil {
		return err
	}
	env.Infof("created user %s", name)
	if !removable {
		return nil
	}
	return env.Undo("remove user "+name, "deluser", name)
}

// WriteSudoers writes and validates the sudoers drop-in. An invalid file is
// never left in place: visudo checks a temporary copy first.
func WriteSudoers(ctx context.Context, env *module.Env, user string, nopasswd bool) (bool, error) {
	content := RenderSudoers(user, nopasswd)
	file := SudoersFile(user)
	if sys.ReadString(env.Sys, file) == content {
		return false, nil
	}
	// sudo ignores files with a dot in their name, so the temp file is inert.
	tmp := path.Join(path.Dir(file), ".server-init-check")
	if err := env.Sys.WriteFile(tmp, []byte(content), 0o440); err != nil {
		return false, err
	}
	_, err := env.Sys.Run(ctx, sys.Command("visudo", "-cf", tmp))
	_ = env.Sys.Remove(tmp)
	if err != nil {
		return false, fmt.Errorf("sudoers validation failed: %w", err)
	}
	return env.PutFile(file, content, 0o440)
}
