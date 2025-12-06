package hooks

import (
	"secure-mcp-gateway/pkg/mcp"
	"secure-mcp-gateway/pkg/risk"
)

// PreHook is executed before the actual tool call.
type PreHook interface {
	Name() string
	Execute(req *mcp.JSONRPCRequest, rc *risk.RiskContext) error
}

// PostHook is executed after the tool call, before returning to the agent.
type PostHook interface {
	Name() string
	Execute(req *mcp.JSONRPCRequest, res *mcp.JSONRPCResponse, rc *risk.RiskContext) error
}

// Registry manages the collection of hooks.
type Registry struct {
	PreHooks  []PreHook
	PostHooks []PostHook
}

func NewRegistry() *Registry {
	return &Registry{
		PreHooks:  make([]PreHook, 0),
		PostHooks: make([]PostHook, 0),
	}
}

func (r *Registry) RegisterPre(h PreHook) {
	r.PreHooks = append(r.PreHooks, h)
}

func (r *Registry) RegisterPost(h PostHook) {
	r.PostHooks = append(r.PostHooks, h)
}

// RunPreHooks executes all pre-hooks. If one sets rc.Blocked, it returns early.
func (r *Registry) RunPreHooks(req *mcp.JSONRPCRequest, rc *risk.RiskContext) error {
	for _, h := range r.PreHooks {
		if err := h.Execute(req, rc); err != nil {
			return err
		}
		if rc.Blocked {
			return nil // Stopped by a hook
		}
	}
	return nil
}

// RunPostHooks executes all post-hooks.
func (r *Registry) RunPostHooks(req *mcp.JSONRPCRequest, res *mcp.JSONRPCResponse, rc *risk.RiskContext) error {
	for _, h := range r.PostHooks {
		if err := h.Execute(req, res, rc); err != nil {
			return err
		}
		if rc.Blocked {
			return nil
		}
	}
	return nil
}
