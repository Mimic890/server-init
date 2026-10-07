package module

import (
	"context"
	"testing"

	"charm.land/huh/v2"
)

type fake struct {
	id  string
	req bool
}

func (f fake) ID() string                                { return f.id }
func (f fake) Name() string                              { return f.id }
func (f fake) Description() string                       { return "" }
func (f fake) Form(*Env) []*huh.Group                    { return nil }
func (f fake) Check(context.Context, *Env) (Plan, error) { return Plan{}, nil }
func (f fake) Apply(context.Context, *Env, Plan) error   { return nil }
func (f fake) Rollback(context.Context, *Env) error      { return nil }
func (f fake) Required() bool                            { return f.req }

func TestSelect(t *testing.T) {
	r := NewRegistry(fake{id: "preflight", req: true}, fake{id: "system"}, fake{id: "ssh"}, fake{id: "ufw"})
	got, err := r.Select(ParseList("ufw, ssh"))
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, m := range got {
		ids = append(ids, m.ID())
	}
	if want := "preflight ssh ufw"; join(ids) != want {
		t.Fatalf("got %v, want apply order %s", ids, want)
	}
	if _, err := r.Select([]string{"nope"}); err == nil {
		t.Fatal("unknown module must fail")
	}
	all, _ := r.Select(nil)
	if len(all) != 4 {
		t.Fatalf("empty selection = all, got %d", len(all))
	}
}

func join(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += " "
		}
		out += x
	}
	return out
}
