// Package modules lists all modules in apply order.
package modules

import (
	"github.com/mimic890/server-init/internal/module"
	"github.com/mimic890/server-init/internal/modules/preflight"
)

// Registry returns every module in apply order.
func Registry() *module.Registry {
	return module.NewRegistry(
		preflight.New(),
	)
}
