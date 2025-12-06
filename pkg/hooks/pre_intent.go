package hooks

import (
	"encoding/json"
	"strings"

	"secure-mcp-gateway/pkg/config"
	"secure-mcp-gateway/pkg/mcp"
	"secure-mcp-gateway/pkg/ml"
	"secure-mcp-gateway/pkg/risk"
)

type IntentHook struct {
	Config *config.SecurityConfig
	Scorer *ml.ThreatScorer
}

func NewIntentHook(cfg *config.SecurityConfig) *IntentHook {
	return &IntentHook{
		Config: cfg,
		Scorer: ml.NewThreatScorer(),
	}
}

func (h *IntentHook) Name() string {
	return "DeepIntentAnalyzer"
}

func (h *IntentHook) Execute(req *mcp.JSONRPCRequest, rc *risk.RiskContext) error {
	// Inspect Arguments
	argsBytes, _ := req.Params.MarshalJSON()
	argsStr := strings.ToLower(string(argsBytes))

	// 1. ML-Based Anomaly Detection (The "Smart" Layer)
	// Canonicalize: In production, we'd translate foreign text here before evaluation.
	// For now, the ML model has a 'Non-ASCII' penalty.
	mlScore := h.Scorer.Evaluate(string(argsBytes))
	if mlScore > 0.75 {
		// Convert probability (0.0-1.0) to Risk Score (0-100)
		riskPoints := int(mlScore * 100)
		rc.AddRisk(riskPoints, "ML Model detected anomaly (Confidence: High)")
	}

	// 2. Symbolic/Rule-Based Detection (The "Deterministic" Layer)
	for _, rule := range h.Config.IntentRules {
		// Special tool check
		if rule.Name == "High Risk Tooling" && req.Method == "tools/call" {
			var params mcp.CallToolParams
			if err := json.Unmarshal(req.Params, &params); err == nil {
				for _, p := range rule.Patterns {
					if params.Name == p {
						rc.AddRisk(rule.RiskScore, "High-Risk Tool: "+p)
					}
				}
			}
			continue
		}

		// Pattern checks
		for _, pattern := range rule.Patterns {
			if strings.Contains(argsStr, pattern) {
				if rule.ForceBlock {
					rc.ForceBlock("Critical Signature: " + rule.Name)
					return nil
				}
				rc.AddRisk(rule.RiskScore, rule.Description+": '"+pattern+"'")
			}
		}
	}
	return nil
}
