// Package check holds the result types shared by the security audit and the
// malware scan: findings grouped by category, a score and a renderer.
package check

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// Status is the verdict of one finding.
type Status int

const (
	OK   Status = iota // as it should be
	Info               // worth knowing, not a problem by itself
	Warn               // should be fixed
	Fail               // a real problem
	Skip               // could not be checked
)

func (s Status) String() string {
	return [...]string{"ok", "info", "warning", "problem", "skipped"}[s]
}

// Finding is the result of one check.
type Finding struct {
	Category string
	Title    string
	Status   Status
	// Summary is one line next to the title.
	Summary string
	// Details are extra lines (files, ports, processes).
	Details []string
	// Fix tells how to fix it, e.g. "server-init → Manage → SSH".
	Fix string
}

// Report is the result of an audit or a scan.
type Report struct {
	Title    string
	Findings []Finding
	Duration time.Duration
}

// Add appends a finding.
func (r *Report) Add(f Finding) { r.Findings = append(r.Findings, f) }

// Count returns how many findings have status s.
func (r Report) Count(s Status) int {
	n := 0
	for _, f := range r.Findings {
		if f.Status == s {
			n++
		}
	}
	return n
}

// Score is 0-100: OK counts fully, a warning half, a problem not at all.
// Info and skipped findings do not count.
func (r Report) Score() int {
	ok, warn, fail := r.Count(OK), r.Count(Warn), r.Count(Fail)
	total := ok + warn + fail
	if total == 0 {
		return 100
	}
	return (200*ok + 100*warn) / (2 * total)
}

// Styles colors the rendered report.
type Styles struct {
	OK, Info, Warn, Fail, Dim, Bold func(string) string
}

func id(s string) string { return s }

// Plain renders without colors.
var Plain = Styles{OK: id, Info: id, Warn: id, Fail: id, Dim: id, Bold: id}

// MaxDetails limits the detail lines printed per finding.
const MaxDetails = 15

// Render writes the report: a summary line, then every category with its
// findings, problems first inside a category.
func Render(w io.Writer, r Report, st Styles) {
	icon := map[Status]string{
		OK: st.OK("✓"), Info: st.Info("•"), Warn: st.Warn("!"), Fail: st.Fail("✗"), Skip: st.Dim("-"),
	}
	score := fmt.Sprintf("%d/100", r.Score())
	switch s := r.Score(); {
	case s >= 90:
		score = st.OK(score)
	case s >= 60:
		score = st.Warn(score)
	default:
		score = st.Fail(score)
	}
	_, _ = fmt.Fprintf(w, "%s  score %s  ·  %s  %s  %s",
		st.Bold(r.Title), score,
		st.Fail(fmt.Sprintf("%d problem(s)", r.Count(Fail))),
		st.Warn(fmt.Sprintf("%d warning(s)", r.Count(Warn))),
		st.OK(fmt.Sprintf("%d ok", r.Count(OK))))
	if r.Duration > 0 {
		_, _ = fmt.Fprint(w, st.Dim(fmt.Sprintf("  (%s)", r.Duration.Round(100*time.Millisecond))))
	}
	_, _ = fmt.Fprintln(w)

	var cats []string
	by := map[string][]Finding{}
	for _, f := range r.Findings {
		if _, ok := by[f.Category]; !ok {
			cats = append(cats, f.Category)
		}
		by[f.Category] = append(by[f.Category], f)
	}
	for _, c := range cats {
		_, _ = fmt.Fprintf(w, "\n%s\n", st.Bold(c))
		fs := by[c]
		for _, want := range []Status{Fail, Warn, Info, OK, Skip} {
			for _, f := range fs {
				if f.Status != want {
					continue
				}
				line := "  " + icon[f.Status] + " " + f.Title
				if f.Summary != "" {
					line += st.Dim(": ") + f.Summary
				}
				_, _ = fmt.Fprintln(w, line)
				for i, d := range f.Details {
					if i == MaxDetails {
						_, _ = fmt.Fprintln(w, st.Dim(fmt.Sprintf("      ... and %d more", len(f.Details)-MaxDetails)))
						break
					}
					_, _ = fmt.Fprintln(w, st.Dim("      "+d))
				}
				if f.Fix != "" && (f.Status == Warn || f.Status == Fail) {
					_, _ = fmt.Fprintln(w, "      "+st.Info("fix: "+f.Fix))
				}
			}
		}
	}
}

// String renders the report without colors.
func (r Report) String() string {
	var b strings.Builder
	Render(&b, r, Plain)
	return b.String()
}
