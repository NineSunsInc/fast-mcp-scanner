package hooks

import (
	"encoding/json"

	"secure-mcp-gateway/pkg/config"
	"secure-mcp-gateway/pkg/mcp"
	"secure-mcp-gateway/pkg/ml"
	"secure-mcp-gateway/pkg/risk"
)

// IndirectInjectionHook scans *Outputs* for attacks.
// If an agent reads a file that says "Ignore previous instructions", we must catch it here.
type IndirectInjectionHook struct {
	Config *config.SecurityConfig
	Scorer *ml.ThreatScorer
}

func NewIndirectInjectionHook(cfg *config.SecurityConfig) *IndirectInjectionHook {
	return &IndirectInjectionHook{
		Config: cfg,
		Scorer: ml.NewThreatScorer(),
	}
}

func (h *IndirectInjectionHook) Name() string {
	return "IndirectInjectionDefense"
}

func (h *IndirectInjectionHook) Execute(req *mcp.JSONRPCRequest, res *mcp.JSONRPCResponse, rc *risk.RiskContext) error {
	var resultStr string

	// Extract content from result
	if toolRes, ok := res.Result.(mcp.CallToolResult); ok {
		for _, c := range toolRes.Content {
			resultStr += c.Text
		}
	} else {
		b, _ := json.Marshal(res.Result)
		resultStr = string(b)
	}

	// 1. Run Threat Scorer on the OUTPUT content
	// This is critical: We are checking if the *World* is trying to hack the *Agent*.
	score := h.Scorer.Evaluate(resultStr)
	if score > 0.8 {
		rc.AddRisk(int(score*100), "Indirect Injection Detected in Tool Output")

		// Action: Sanitize content before returning to Agent
		// We replace the dangerous text with a warning
		res.Result = map[string]string{
			"error": "Security Warning: The content retrieved contained malicious instructions and was redacted.",
		}
	}

	return nil
}
