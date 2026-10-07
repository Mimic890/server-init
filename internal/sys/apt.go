package sys

import (
	"context"
	"strings"
)

// PkgInstalled reports whether a Debian package is installed.
func PkgInstalled(ctx context.Context, s System, pkg string) bool {
	out, err := s.Query(ctx, "dpkg-query", "-W", "-f=${Status}", pkg)
	return err == nil && strings.Contains(out, "install ok installed")
}

// MissingPkgs returns the packages from pkgs that are not installed.
func MissingPkgs(ctx context.Context, s System, pkgs ...string) []string {
	var miss []string
	for _, p := range pkgs {
		if !PkgInstalled(ctx, s, p) {
			miss = append(miss, p)
		}
	}
	return miss
}

var aptOpts = []string{"-y", "-q", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}

// AptUpdate runs apt-get update.
func AptUpdate(ctx context.Context, s System) error {
	_, err := s.Run(ctx, Command("apt-get", "update", "-q"))
	return err
}

// AptInstall installs packages (existing config files are kept).
func AptInstall(ctx context.Context, s System, pkgs ...string) error {
	if len(pkgs) == 0 {
		return nil
	}
	args := append([]string{"install", "--no-install-recommends"}, aptOpts...)
	_, err := s.Run(ctx, Command("apt-get", append(args, pkgs...)...))
	return err
}

// AptPurge removes packages together with their configuration.
func AptPurge(ctx context.Context, s System, pkgs ...string) error {
	if len(pkgs) == 0 {
		return nil
	}
	args := append([]string{"purge"}, aptOpts...)
	_, err := s.Run(ctx, Command("apt-get", append(args, pkgs...)...))
	return err
}
