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
	// 1. Check for Invisible Characters & Control Codes in Method
	if containsInvisibleChars(req.Method) {
		rc.AddRisk(30, "Invisible characters detected in Method")
	}

	// 2. Deep Scan of Parameters (The Payload)
	// We marshal the params to a string to scan the raw content
	paramsBytes, _ := req.Params.MarshalJSON()
	paramsStr := string(paramsBytes)

	if containsInvisibleChars(paramsStr) {
		rc.AddRisk(50, "Obfuscation: Invisible characters (Zero-Width) detected in params")
	}
	if strings.Contains(paramsStr, "\\u0000") || strings.Contains(paramsStr, "\x00") {
		rc.AddRisk(90, "CRITICAL: Null Byte Injection detected")
	}

	// 3. Protocol Validation
	if req.JSONRPC != "2.0" {
		rc.AddRisk(10, "Invalid JSON-RPC version")
	}

	// 4. Method Whitelisting (Basic)
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
