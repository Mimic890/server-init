package module

import (
	"fmt"
	"slices"
	"strings"
)

// Registry is the ordered list of modules (apply order).
type Registry struct {
	mods []Module
}

// NewRegistry returns a registry with mods in apply order.
func NewRegistry(mods ...Module) *Registry { return &Registry{mods: mods} }

// All returns every module in apply order.
func (r *Registry) All() []Module { return slices.Clone(r.mods) }

// Get returns the module with id.
func (r *Registry) Get(id string) (Module, bool) {
	for _, m := range r.mods {
		if m.ID() == id {
			return m, true
		}
	}
	return nil, false
}

// IDs returns all module IDs in apply order.
func (r *Registry) IDs() []string {
	ids := make([]string, len(r.mods))
	for i, m := range r.mods {
		ids[i] = m.ID()
	}
	return ids
}

// IsRequired reports whether m always runs.
func IsRequired(m Module) bool {
	rq, ok := m.(Required)
	return ok && rq.Required()
}

// Select returns the modules named in ids (plus required ones) in apply
// order. Empty ids selects everything.
func (r *Registry) Select(ids []string) ([]Module, error) {
	for _, id := range ids {
		if _, ok := r.Get(id); !ok {
			return nil, fmt.Errorf("unknown module %q (known: %s)", id, strings.Join(r.IDs(), ", "))
		}
	}
	var out []Module
	for _, m := range r.mods {
		if len(ids) == 0 || IsRequired(m) || slices.Contains(ids, m.ID()) {
			out = append(out, m)
		}
	}
	return out, nil
}

// ParseList splits "ssh,ufw" into IDs.
func ParseList(s string) []string {
	var ids []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			ids = append(ids, f)
		}
	}
	return ids
}
