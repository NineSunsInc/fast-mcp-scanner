package kernel

import (
	"fmt"
)

// evaluatePolicy applies the logic gates on the Features.
// This is the "Decision Matrix".
func (k *Kernel) evaluatePolicy(fs *FeatureSet) *Decision {
	d := &Decision{Allow: true, RiskScore: 0}

	// 1. Hard Blocks (Sanity)
	if fs.IsSessionLocked {
		d.Allow = false
		d.RiskScore = 100
		d.BlockReason = "Session Locked (Behavioral Ban)"
		return d
	}
	if fs.HasNullBytes {
		d.Allow = false
		d.RiskScore = 100
		d.BlockReason = "Null Byte Injection Detected"
		return d
	}

	// 2. Risk Accumulation (Soft Signals)
	baseRisk := 0
	contextRisk := 0

	// ML Text Score (0.0 - 1.0)
	mlScore := fs.TextRiskScore

	// Sensitive Tool Penalty
	if fs.IsSensitiveTool {
		baseRisk += 35 // High Baseline Risk for write/delete/exec
	}

	// Psychological
	if fs.PsychUrgency {
		baseRisk += 40
	}
	if fs.PsychImpersonation {
		baseRisk += 50
	}

	// Structural Obfuscation
	if fs.HasHiddenChars {
		baseRisk += 30
	}
	if fs.HasNullBytes {
		baseRisk += 50 // Null bytes should be near instant block
	}

	// 3. Contextual Risk (Session History)
	// If the session has a history of bad behavior, risk starts higher.
	// But we scale it down so it's not instant-kill unless very bad.
	contextRisk = int(fs.SessionRiskScore / 5) // 100 Session Risk -> +20 Context Risk

	if fs.SessionRiskScore > 50 {
		contextRisk += 30 // Was 20
	}
	if fs.SessionRiskScore > 80 {
		contextRisk += 50
	}

	if fs.IsSessionLocked {
		// Lockdown mode
		return &Decision{
			Allow:       false,
			RiskScore:   100,
			BlockReason: "Session Locked: Excessive Violations",
		}
	}

	// Combine all risk factors
	score := baseRisk + contextRisk + int(mlScore*100)

	d.RiskScore = score

	// 4. Final Threshold (Dynamic)
	// Default: 60. Lowered if session is already compromised.
	threshold := 60
	if fs.SessionRiskScore > 100 {
		threshold = 40
	}

	if score >= threshold {
		d.Allow = false
		if fs.IsSensitiveTool {
			d.BlockReason = fmt.Sprintf("Sensitive Tool Usage: %s", fs.ToolName)
		} else if fs.HasHiddenChars {
			d.BlockReason = "Malicious Payload Detected (Obfuscation)"
		} else {
			d.BlockReason = fmt.Sprintf("Risk Threshold Exceeded (Score: %d)", score)
		}
	}

	return d
}
