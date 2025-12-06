package hooks

import (
	"encoding/json"
	"strings"

	"secure-mcp-gateway/pkg/mcp"
	"secure-mcp-gateway/pkg/risk"
	"secure-mcp-gateway/pkg/scanner"
)

type CDRHook struct {
	Scanner *scanner.DeepScanner
}

func (h *CDRHook) Name() string {
	return "MultimodalCDR"
}

func (h *CDRHook) Execute(req *mcp.JSONRPCRequest, rc *risk.RiskContext) error {
	// Only inspect 'tools/call' params
	if req.Method != "tools/call" {
		return nil
	}

	var params mcp.CallToolParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil
	}

	h.Scanner = scanner.NewDeepScanner()

	// Recursive scan of all arguments finding "base64" or "image" keys
	// Simplified loop for flat arguments map
	for key, val := range params.Arguments {
		valStr, ok := val.(string)
		if !ok {
			continue
		}

		// Heuristic: Is this a file?
		if strings.Contains(key, "image") || strings.Contains(key, "file") || len(valStr) > 512 {
			res := h.Scanner.ScanBase64(valStr)
			if !res.IsSafe {
				rc.ForceBlock("Deep Scanner: " + strings.Join(res.Findings, ", "))
				return nil
			}
			if res.RiskScore > 0 {
				rc.AddRisk(res.RiskScore, "File Analysis: "+strings.Join(res.Findings, ", "))
			}

			// CDR Action: If it passed checks but still risky, we claim to transcode it.
			// In a real proxy, we would replace parameters.Arguments[key] with sanitized version.
			// params.Arguments[key] = transcode(valStr)
		}
	}

	return nil
}
