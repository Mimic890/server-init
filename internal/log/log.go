// Package log writes the run log (/var/log/server-init.log) and forwards
// user-visible lines to the UI.
package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultPath is the log file.
const DefaultPath = "/var/log/server-init.log"

// Line is one user-visible log line.
type Line struct {
	Time   time.Time
	Level  slog.Level
	Module string
	Msg    string
}

// Open opens the log file for appending. On failure it logs nowhere (the
// program still works, e.g. as non-root in --dry-run).
func Open(path string) io.WriteCloser {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nopCloser{io.Discard}
	}
	return f
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

// New returns a logger that writes everything (debug included) to file and
// passes info+ lines to sink (may be nil).
func New(file io.Writer, sink func(Line)) *slog.Logger {
	return slog.New(&handler{file: file, sink: sink, mu: &sync.Mutex{}})
}

type handler struct {
	file  io.Writer
	sink  func(Line)
	attrs []slog.Attr
	mu    *sync.Mutex
}

func (h *handler) Enabled(context.Context, slog.Level) bool { return true }

func (h *handler) Handle(_ context.Context, r slog.Record) error {
	module := ""
	var extra []string
	add := func(a slog.Attr) {
		if a.Key == "module" {
			module = a.Value.String()
			return
		}
		extra = append(extra, a.Key+"="+fmt.Sprintf("%q", a.Value.String()))
	}
	for _, a := range h.attrs {
		add(a)
	}
	r.Attrs(func(a slog.Attr) bool { add(a); return true })

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.file != nil {
		prefix := ""
		if module != "" {
			prefix = "[" + module + "] "
		}
		tail := ""
		if len(extra) > 0 {
			tail = " " + strings.Join(extra, " ")
		}
		_, _ = fmt.Fprintf(h.file, "%s %-5s %s%s%s\n", r.Time.Format("2006-01-02 15:04:05"), r.Level, prefix, r.Message, tail)
	}
	if h.sink != nil && r.Level >= slog.LevelInfo {
		h.sink(Line{Time: r.Time, Level: r.Level, Module: module, Msg: r.Message})
	}
	return nil
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &c
}

func (h *handler) WithGroup(string) slog.Handler { return h }

// Sink forwards lines to a receiver that can be attached later (the TUI
// program exists only after the logger was created).
type Sink struct {
	mu sync.Mutex
	fn func(Line)
}

// Set attaches the receiver; nil detaches it.
func (s *Sink) Set(fn func(Line)) {
	s.mu.Lock()
	s.fn = fn
	s.mu.Unlock()
}

// Write passes l to the receiver, if any.
func (s *Sink) Write(l Line) {
	s.mu.Lock()
	fn := s.fn
	s.mu.Unlock()
	if fn != nil {
		fn(l)
	}
}
