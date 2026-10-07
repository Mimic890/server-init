package scan

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mimic890/server-init/internal/check"
	"github.com/mimic890/server-init/internal/sys"
)

// ClamAV needs about 1 GB of memory for its signatures.
const clamMinMemMB = 1100

// clamTargets are where malware is usually found on a server.
var clamTargets = []string{"/root", "/home", "/tmp", "/var/tmp", "/dev/shm", "/var/www", "/srv", "/opt", "/usr/local",
	"/etc", "/var/spool/cron"}

// signature wait (replaced in tests)
var (
	sigTimeout = 15 * time.Minute
	sigPoll    = 5 * time.Second
)

// AvailableMB returns MemAvailable + SwapFree from /proc/meminfo.
func AvailableMB(meminfo string) int {
	total := 0
	for _, l := range strings.Split(meminfo, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && (f[0] == "MemAvailable:" || f[0] == "SwapFree:") {
			kb, _ := strconv.Atoi(f[1])
			total += kb / 1024
		}
	}
	return total
}

func (h *host) clamav() {
	add := func(st check.Status, summary string, details []string, fix string) {
		h.add(catClam, "ClamAV scan", st, summary, details, fix)
	}
	if mb := AvailableMB(h.read("/proc/meminfo")); mb > 0 && mb < clamMinMemMB {
		add(check.Skip, fmt.Sprintf("needs about %d MB of free memory, %d MB available", clamMinMemMB, mb), nil,
			"add swap (server-init → Custom setup → Kernel and swap) and run it again")
		return
	}
	if !sys.Has(h.s, "clamscan") {
		if h.s.DryRun() {
			add(check.Skip, "dry run: clamav would be installed now", nil, "")
			return
		}
		h.progress("installing clamav (apt-get install clamav clamav-freshclam)")
		if err := sys.AptUpdate(h.ctx, h.s); err != nil {
			add(check.Skip, "apt-get update failed: "+err.Error(), nil, "")
			return
		}
		if err := sys.AptInstall(h.ctx, h.s, "clamav", "clamav-freshclam"); err != nil {
			add(check.Skip, "cannot install clamav: "+err.Error(), nil, "")
			return
		}
	}
	if err := h.signatures(); err != nil {
		add(check.Skip, err.Error(), nil, "")
		return
	}

	var targets []string
	for _, t := range clamTargets {
		if sys.Exists(h.s, t) {
			targets = append(targets, t)
		}
	}
	h.progress("scanning %s with ClamAV (can take several minutes)", strings.Join(targets, " "))
	args := append([]string{"--recursive", "--infected", "--no-summary", "--cross-fs=no",
		"--max-filesize=100M", "--max-scansize=300M"}, targets...)
	out, err := h.query("clamscan", args...)
	found := ParseClamscan(out)
	ver, _ := h.query("clamscan", "--version")
	ver = strings.TrimSpace(ver)
	switch {
	case len(found) > 0:
		add(check.Fail, fmt.Sprintf("%d infected file(s)", len(found)), found,
			"delete or quarantine the files, then find out how they got there")
	case err != nil && !strings.Contains(err.Error(), "exit status 1"):
		add(check.Skip, "clamscan failed: "+firstLine(err.Error()), nil, "")
	default:
		add(check.OK, "nothing found in "+strings.Join(targets, " "), []string{ver}, "")
	}
}

// signatures makes sure the virus database is there, waiting for the
// freshclam service after a fresh install.
func (h *host) signatures() error {
	have := func() bool {
		main, _ := h.s.Glob("/var/lib/clamav/main.c[vl]d")
		daily, _ := h.s.Glob("/var/lib/clamav/daily.c[vl]d")
		return len(main) > 0 && len(daily) > 0
	}
	if have() {
		return nil
	}
	if !sys.UnitActive(h.ctx, h.s, "clamav-freshclam") {
		h.progress("downloading the virus signatures (freshclam, about 300 MB)")
		if _, err := h.s.Run(h.ctx, sys.Command("freshclam", "--stdout")); err != nil && !have() {
			return fmt.Errorf("freshclam failed: %s", firstLine(err.Error()))
		}
		return nil
	}
	h.progress("waiting for the freshclam service to download the virus signatures (about 300 MB)")
	deadline := time.Now().Add(sigTimeout)
	for !have() {
		if time.Now().After(deadline) {
			return fmt.Errorf("virus signatures not downloaded after %s (see journalctl -u clamav-freshclam)", sigTimeout)
		}
		select {
		case <-h.ctx.Done():
			return h.ctx.Err()
		case <-time.After(sigPoll):
		}
	}
	return nil
}

// ParseClamscan returns the "path: Signature FOUND" lines.
func ParseClamscan(out string) []string {
	var found []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasSuffix(strings.TrimSpace(l), " FOUND") {
			found = append(found, strings.TrimSpace(l))
		}
	}
	return found
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}
