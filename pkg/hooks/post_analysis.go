package hooks

import (
	"encoding/json"
	"math"
	"strings"

	"secure-mcp-gateway/pkg/config"
	"secure-mcp-gateway/pkg/mcp"
	"secure-mcp-gateway/pkg/risk"
)

// --- Taint Hook ---
type TaintHook struct {
	Config *config.SecurityConfig
}

func NewTaintHook(cfg *config.SecurityConfig) *TaintHook {
	return &TaintHook{Config: cfg}
}

func (h *TaintHook) Name() string {
	return "TaintAnalyzer"
}

func (h *TaintHook) Execute(req *mcp.JSONRPCRequest, res *mcp.JSONRPCResponse, rc *risk.RiskContext) error {
	// Check for Canary Tokens in the Output
	resBytes, _ := json.Marshal(res.Result)
	resStr := string(resBytes)

	for _, canary := range h.Config.Canaries {
		if strings.Contains(resStr, canary.Token) {
			rc.ForceBlock("CRITICAL: Data Leakage Detected (Canary Found: " + canary.Description + ")")
			res.Result = "[REDACTED BY SECURITY GATEWAY]"
			return nil
		}
	}
	return nil
}

// --- Entropy Hook ---
type EntropyHook struct{}

func (h *EntropyHook) Name() string {
	return "EntropyScanner"
}

func (h *EntropyHook) Execute(req *mcp.JSONRPCRequest, res *mcp.JSONRPCResponse, rc *risk.RiskContext) error {
	// Calculate Shannon Entropy of the Result
	// High entropy (> 6.0) often indicates encryption or compressed binaries (exfiltration)

	var resultStr string

	// Try to extract text content
	if toolRes, ok := res.Result.(mcp.CallToolResult); ok {
		for _, c := range toolRes.Content {
			resultStr += c.Text
		}
	} else {
		// Fallback to JSON string
		b, _ := json.Marshal(res.Result)
		resultStr = string(b)
	}

	if len(resultStr) < 100 {
		return nil // Too short to matter
	}

	e := shannonEntropy(resultStr)
	if e > 6.0 {
		rc.AddRisk(40, "High Entropy Output (Possible Exfiltration)")
	}

	return nil
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	l := float64(len(s))
	e := 0.0
	for _, c := range freq {
		p := c / l
		e -= p * math.Log2(p)
	}
	return e
}
