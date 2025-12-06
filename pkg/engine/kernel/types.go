package kernel

import (
	"secure-mcp-gateway/pkg/engine/session"
	"secure-mcp-gateway/pkg/mcp"
)

// AnalysisContext holds all raw inputs and derived features for a single request.
type AnalysisContext struct {
	Request      *mcp.JSONRPCRequest
	SessionState *session.SessionState
	RequestID    string
	Timestamp    int64
}

// FeatureSet represents the extracted security signals.
// This is the "Shared State" derived from sensors.
type FeatureSet struct {
	// 1. Text / Semantics
	FullText      string  // Canonicalized text (including OCR)
	TextRiskScore float64 // 0.0 - 1.0 (from ThreatScorer)

	// 2. Content / Structural
	HasNullBytes   bool
	HasHiddenChars bool

	// Tool Risks
	ToolName        string
	IsSensitiveTool bool

	// Risk Scores
	IsShellcode   bool
	FileRiskScore int

	// 3. Psychological
	PsychUrgency       bool
	PsychImpersonation bool

	// 4. Behavioral (Context)
	SessionRiskScore int // Current cumulative risk from session
	IsSessionLocked  bool
}

// Decision is the final output of the Kernel.
type Decision struct {
	Allow       bool
	BlockReason string
	RiskScore   int // Final normalized score (0-100)
}
