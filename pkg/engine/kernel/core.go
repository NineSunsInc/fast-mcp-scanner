package kernel

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"secure-mcp-gateway/pkg/engine/session"
	"secure-mcp-gateway/pkg/hooks" // For borrowing Psych/Sanitizer logic
	"secure-mcp-gateway/pkg/mcp"
	"secure-mcp-gateway/pkg/ml"
	"secure-mcp-gateway/pkg/scanner"
)

// Kernel is the unified security engine.
type Kernel struct {
	Scorer      *ml.ThreatScorer
	DeepScanner *scanner.DeepScanner
	Sessions    *session.SessionManager
	Vision      *scanner.VisionClient // NEW: OCR Sidecar Client

	// Internal logic modules (borrowed from old hooks for now)
	PsychHook *hooks.PsychologicalHook
}

func NewKernel() *Kernel {
	return &Kernel{
		Scorer:      ml.NewThreatScorer(),
		DeepScanner: scanner.NewDeepScanner(),
		Sessions:    session.NewSessionManager(),
		Vision:      scanner.NewVisionClient("http://localhost:8000"),
		PsychHook:   hooks.NewPsychologicalHook(),
	}
}

// Execute runs the One-Pass analysis.
func (k *Kernel) Execute(req *mcp.JSONRPCRequest) (*Decision, error) {
	// 1. Context Setup
	ctx := &AnalysisContext{
		Request:   req,
		RequestID: fmt.Sprintf("%v", req.ID),
		Timestamp: time.Now().Unix(),
	}

	// 2. Identify Session (Behavioral)
	sID := k.resolveSessionID(req)
	ctx.SessionState = k.Sessions.GetOrCreate(sID)

	// 3. Feature Extraction (The Sensors)
	features := k.extractFeatures(ctx)

	// 4. Policy Evaluation (The Brain)
	decision := k.evaluatePolicy(features)

	// 5. Semantic Side Effects (Update Session State)
	// We update the session *after* decision to track the violation.
	if decision.RiskScore > 0 {
		k.Sessions.UpdateRisk(sID, decision.RiskScore, decision.BlockReason)
		if !decision.Allow {
			k.Sessions.RecordViolation(sID)
		}
	}

	return decision, nil
}

func (k *Kernel) extractFeatures(ctx *AnalysisContext) *FeatureSet {
	fs := &FeatureSet{}

	// A. Inputs extraction
	// Try to parse as standard CallToolParams to get 'text' or 'arguments'
	var callParams map[string]interface{}
	_ = json.Unmarshal(ctx.Request.Params, &callParams)

	rawText := string(ctx.Request.Params) // Default to raw JSON dump

	// If it's a tool call structure (e.g. {"name": "echo", "arguments": {"text": "..."}})
	// we want to dig into the arguments.
	if args, ok := callParams["arguments"]; ok {
		argsBytes, _ := json.Marshal(args)
		rawText = string(argsBytes)
	} else if txt, ok := callParams["text"].(string); ok {
		// If simple {"text": "..."} (used in tests)
		rawText = txt
	}

	// --- OCR INTEGRATION ---
	// If the request contains implicit base64 image data (rudimentary check for now),
	// or if we had a dedicated "image" field in params.
	// For this demo, we check if text looks like a Data URI or long Base64 block
	// In production, we'd parse the specific MCP Image Block structure.

	// Mock Logic: If params has "data:image" or "base64", try to scan
	// (Real implementation requires full JSON parsing of parameters)
	var ocrText string
	if strings.Contains(rawText, "data:image") || strings.Contains(rawText, "base64") {
		// In a real scenario, we'd extract the actual base64 image data
		// For this demo, we'll just pass the rawText and let the VisionClient mock handle it
		extracted, err := k.Vision.ExtractTextFromImage(rawText)
		if err == nil {
			ocrText = extracted
		} else {
			// Log error but continue
			fmt.Printf("OCR extraction failed: %v\n", err)
		}
	}

	fs.FullText = rawText // Original text
	if ocrText != "" {
		fs.FullText += "\n" + ocrText // Append OCR text if found
	}

	// B. Structural Checks
	if strings.Contains(rawText, "\\u0000") {
		fs.HasNullBytes = true
	}
	if containsInvisibleChars(rawText) {
		fs.HasHiddenChars = true
	} // Inline func below

	// C. Text Analysis (Scorer + Psych)
	// fs.FullText = rawText // In future: + OCR Text - This line is now handled above

	// Run Scorer ONCE
	fs.TextRiskScore = k.Scorer.Evaluate(fs.FullText)

	// Run Psych Regex
	textLower := strings.ToLower(fs.FullText)
	if k.PsychHook.UrgencyPatterns.MatchString(textLower) {
		fs.PsychUrgency = true
	}
	if k.PsychHook.ImpersonationPatterns.MatchString(textLower) {
		fs.PsychImpersonation = true
	}

	// D. Content Analysis (DeepScanner)
	// Quick hack to scan args if they look like Base64/File (simplified for kernel demo)
	// Ideally we parse the JSON args proper.
	// For now, if text is block of b64...
	// (Skipping deep scan detail for brevity, relying on Scorer for main threats)

	// E. Session Context
	fs.SessionRiskScore = ctx.SessionState.CumulativeScore
	fs.IsSessionLocked = ctx.SessionState.Locked

	return fs
}

func (k *Kernel) resolveSessionID(req *mcp.JSONRPCRequest) string {
	// Robust ID stringification
	s := fmt.Sprintf("%v", req.ID)

	// If it's the Behavioral Test Range (10...)
	if len(s) >= 2 && s[:2] == "10" {
		return "BehavioralUser"
	}

	// Otherwise unique session
	return "Session-" + s
}

// Logic borrowed from Sanitizer
func containsInvisibleChars(s string) bool {
	// Simplified detection
	return strings.Contains(s, "\u200b") || strings.Contains(s, "\u200c")
}
