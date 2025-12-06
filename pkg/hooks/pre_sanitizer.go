package hooks

import (
	"strings"
	"unicode"

	"secure-mcp-gateway/pkg/mcp"
	"secure-mcp-gateway/pkg/risk"
)

type SanitizerHook struct{}

func (h *SanitizerHook) Name() string {
	return "ProtocolSanitizer"
}

func (h *SanitizerHook) Execute(req *mcp.JSONRPCRequest, rc *risk.RiskContext) error {
	// 1. Check for Invisible Characters (common in prompt injection to hide instructions)
	// e.g., Zero Width Space, Tag Characters
	if containsInvisibleChars(req.Method) {
		rc.AddRisk(30, "Invisible characters detected in Method")
	}

	// 2. Protocol Validation
	if req.JSONRPC != "2.0" {
		rc.AddRisk(10, "Invalid JSON-RPC version")
	}

	// 3. Method Whitelisting (Basic)
	if strings.HasPrefix(req.Method, "_") {
		rc.AddRisk(20, "Internal method call attempted")
	}

	return nil
}

func containsInvisibleChars(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Cf, r) { // Format category (includes zero-width)
			return true
		}
	}
	return false
}
