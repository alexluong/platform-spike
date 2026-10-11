package core

import (
	"fmt"
	"net/http"

	"github.com/alexluong/platform-spike/go/internal/perm"
)

// Module contributes ops to the registry.
type Module interface {
	Ops() []Op
}

// Registry lists every op. It refuses ops whose action is not in the catalog.
type Registry struct {
	ops []Op
}

func (r *Registry) Add(m Module) {
	for _, op := range m.Ops() {
		if op.Auth == AuthAction {
			if _, ok := perm.Get(op.Action); !ok {
				panic(fmt.Sprintf("op %s %s: action %q not in catalog", op.Method, op.Path, op.Action))
			}
		}
		if op.Run == nil {
			panic(fmt.Sprintf("op %s %s: no Run", op.Method, op.Path))
		}
		r.ops = append(r.ops, op)
	}
}

func (r *Registry) Ops() []Op { return r.ops }

// Mount registers every op on mux through the executor.
func (r *Registry) Mount(mux *http.ServeMux, e *Executor) {
	for _, op := range r.ops {
		mux.Handle(op.Method+" "+op.Path, e.Handler(op))
	}
}
