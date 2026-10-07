package check

import (
	"strings"
	"testing"
)

func TestScoreAndRender(t *testing.T) {
	r := Report{Title: "Audit"}
	r.Add(Finding{Category: "SSH", Title: "a", Status: OK})
	r.Add(Finding{Category: "SSH", Title: "b", Status: Warn, Fix: "do b"})
	r.Add(Finding{Category: "SSH", Title: "c", Status: Fail, Summary: "bad", Details: []string{"x"}, Fix: "do c"})
	r.Add(Finding{Category: "Net", Title: "d", Status: Info})
	if r.Score() != 50 {
		t.Fatal(r.Score())
	}
	out := r.String()
	for _, want := range []string{"score 50/100", "1 problem(s)", "  ✗ c: bad\n      x\n      fix: do c", "! b", "✓ a", "Net\n  • d"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Index(out, "✗ c") > strings.Index(out, "✓ a") {
		t.Error("problems must come first")
	}
	if (Report{}).Score() != 100 {
		t.Error("empty report")
	}
}
