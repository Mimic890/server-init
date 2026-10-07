// Command server-init sets up and hardens a fresh Debian 12+ / Ubuntu 24.04+
// server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/x/term"

	"github.com/mimic890/server-init/internal/config"
	"github.com/mimic890/server-init/internal/facts"
	"github.com/mimic890/server-init/internal/log"
	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/modules"
	"github.com/mimic890/server-init/internal/runner"
	"github.com/mimic890/server-init/internal/state"
	"github.com/mimic890/server-init/internal/sys"
	"github.com/mimic890/server-init/internal/tui"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

const usage = `server-init - initial setup and hardening for Debian 12+ / Ubuntu 24.04+

Usage:
  server-init                          interactive menu (TUI)
  server-init --only ssh,ufw           preselect modules for the custom setup
  server-init --dry-run                show planned changes, touch nothing
  server-init --config answers.yaml    non-interactive, all answers preset
  server-init --rollback [module]      undo the last run (or one module)
  server-init f2b <command>            manage fail2ban (see: server-init f2b help)
  server-init ssh finalize             close the old SSH port after a --config run
  server-init --version

Flags:
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("server-init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		only     = fs.String("only", "", "comma-separated list of modules to run")
		dryRun   = fs.Bool("dry-run", false, "show planned changes, change nothing")
		cfgPath  = fs.String("config", "", "answers file (YAML): run without questions")
		yes      = fs.Bool("yes", false, "with --config: apply without asking for confirmation")
		rollback = fs.Bool("rollback", false, "undo the last run; with a module name only that module")
		showVer  = fs.Bool("version", false, "print the version")
	)
	fs.Usage = func() {
		_, _ = fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
		_, _ = fmt.Fprintf(stderr, "\nModules (apply order): %s\n", strings.Join(modules.Registry().IDs(), ", "))
	}

	var sub string
	var subArgs []string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, subArgs = args[0], args[1:]
		args = nil
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVer {
		_, _ = fmt.Fprintf(stdout, "server-init %s\n", version)
		return 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logFile := log.Open(log.DefaultPath)
	defer func() { _ = logFile.Close() }()
	sink := &log.Sink{}
	logger := log.New(logFile, sink.Write)
	logger.Info("server-init started", "version", version, "args", strings.Join(os.Args[1:], " "))

	host := sys.NewReal()
	host.OnCommand = func(c sys.Cmd, out string, err error) {
		if err != nil {
			logger.Debug("cmd failed", "cmd", c.String(), "err", err.Error())
			return
		}
		logger.Debug("cmd", "cmd", c.String(), "out", strings.TrimSpace(out))
	}
	var s sys.System = host
	if *dryRun {
		s = sys.NewDryRun(host, func(action string) { logger.Info("dry-run: " + action) })
	}

	answers, err := loadAnswers(*cfgPath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	env := &module.Env{
		Answers: answers,
		Facts:   facts.Gather(ctx, s, os.Geteuid()),
		Sys:     s,
		Run:     state.NewRun(s, time.Now()),
		Log:     logger,
	}
	reg := modules.Registry()

	if sub != "" {
		fn, ok := modules.Commands()[sub]
		if !ok {
			_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n", sub)
			fs.Usage()
			return 2
		}
		sink.Set(func(l log.Line) { _, _ = fmt.Fprintln(stdout, l.Msg) })
		if err := fn(ctx, env.For(sub), subArgs, stdout); err != nil {
			_, _ = fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		return 0
	}

	if *rollback {
		return doRollback(ctx, env, reg, fs.Args(), sink, stdout, stderr)
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "unexpected arguments: %v\n", fs.Args())
		return 2
	}

	ids := module.ParseList(*only)
	if len(ids) == 0 && *cfgPath != "" {
		ids = answers.Modules
	}
	mods, err := reg.Select(ids)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "error:", err)
		return 2
	}

	opts := tui.Options{
		Version:  version,
		Registry: reg,
		Env:      env,
		DryRun:   *dryRun,
		Only:     ids,
		Commands: modules.Commands(),
		Sink:     sink,
		LogPath:  log.DefaultPath,
	}
	if *cfgPath != "" {
		return tui.RunPlain(ctx, tui.PlainOptions{Options: opts, Modules: mods, Yes: *yes, Out: stdout})
	}
	if !term.IsTerminal(os.Stdin.Fd()) || !term.IsTerminal(os.Stdout.Fd()) {
		_, _ = fmt.Fprintln(stderr, "error: no terminal. Use --config answers.yaml for a non-interactive run.")
		return 2
	}
	res, err := tui.Run(ctx, opts)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	// Leave the result in the terminal after the full-screen UI is gone.
	if *dryRun && len(res.Plans) > 0 {
		_, _ = fmt.Fprint(stdout, plainPlans(res.Modules, res.Plans))
	}
	if res.Applied {
		tui.PrintReport(stdout, res)
		if res.Err != nil {
			return 1
		}
	}
	return 0
}

// loadAnswers reads --config, else the answers saved by the last run, else
// the defaults.
func loadAnswers(path string) (*config.Answers, error) {
	if path != "" {
		return config.Load(path)
	}
	if a, err := config.Load(state.Answers); err == nil {
		return a, nil
	}
	return config.Default(), nil
}

func doRollback(ctx context.Context, env *module.Env, reg *module.Registry, args []string,
	sink *log.Sink, stdout, stderr io.Writer) int {
	if !env.Facts.IsRoot && !env.Sys.DryRun() {
		_, _ = fmt.Fprintln(stderr, "error: run as root")
		return 1
	}
	sink.Set(func(l log.Line) { _, _ = fmt.Fprintln(stdout, l.Msg) })
	defer sink.Set(nil)
	if len(args) == 0 {
		if err := runner.RestoreLatestBackup(ctx, env); err != nil {
			_, _ = fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		return 0
	}
	mods, err := reg.Select(args)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	var only []module.Module
	for _, m := range mods {
		for _, a := range args {
			if m.ID() == a {
				only = append(only, m)
			}
		}
	}
	if err := runner.New(env, only).Rollback(ctx); err != nil {
		_, _ = fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func plainPlans(mods []module.Module, plans []module.Plan) string {
	var b strings.Builder
	b.WriteString("Planned changes (dry run, nothing was changed):\n\n")
	for i, p := range plans {
		name := p.Module
		if i < len(mods) {
			name = mods[i].Name()
		}
		b.WriteString(name + "\n" + p.String() + "\n")
	}
	return b.String()
}
