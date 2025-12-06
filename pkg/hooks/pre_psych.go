package hooks

import (
	"regexp"
	"strings"

	"secure-mcp-gateway/pkg/mcp"
	"secure-mcp-gateway/pkg/risk"
)

// PsychologicalHook detects impersonation and urgency patterns.
type PsychologicalHook struct {
	// Pre-compiled regex for speed
	UrgencyPatterns       *regexp.Regexp
	ImpersonationPatterns *regexp.Regexp
}

func NewPsychologicalHook() *PsychologicalHook {
	return &PsychologicalHook{
		// Match "Urgent", "Immediate", "Deadline", "Consequences"
		UrgencyPatterns: regexp.MustCompile(`(?i)\b(urgent|immediate|deadline|critical|consequence|failed|suspended)\b`),

		// Match "I am CEO", "System Admin", "Debug Mode"
		ImpersonationPatterns: regexp.MustCompile(`(?i)\b(i am|role:?|act as|system admin|ceo|developer|debug mode)\b`),
	}
}

func (h *PsychologicalHook) Name() string {
	return "PsychologicalDefense"
}

func (h *PsychologicalHook) Execute(req *mcp.JSONRPCRequest, rc *risk.RiskContext) error {
	paramsBytes, _ := req.Params.MarshalJSON()
	text := strings.ToLower(string(paramsBytes))

	// 1. Urgency Detection (Scarcity Principal)
	// Attackers often force LLMs to skip checks by creating panic.
	if h.UrgencyPatterns.MatchString(text) {
		rc.AddRisk(25, "Psychological: Artificial Urgency/Panic detected")
	}

	// 2. Impersonation / Authority Bias
	// "I am the developer" or "Act as System Admin"
	if h.ImpersonationPatterns.MatchString(text) {
		rc.AddRisk(40, "Psychological: Authority Impersonation attempt")
	}

	return nil
}
