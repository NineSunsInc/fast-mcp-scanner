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
	score := 0

	// ML Text Score (0.0 - 1.0 -> 0 - 100)
	// We add risk proportionally even if it's low, to allow stacking with Psych/Behavioral
	mlScoreInt := int(fs.TextRiskScore * 100)
	score += mlScoreInt

	// Psychological
	if fs.PsychUrgency {
		score += 40
	} // Increased from 25
	if fs.PsychImpersonation {
		score += 50
	} // Increased from 40

	// Structural Obfuscation
	if fs.HasHiddenChars {
		score += 50
	}

	// 3. Contextual Adjustment (Current Session Risk)
	// If user is already suspicious, we amplify current risk
	if fs.SessionRiskScore > 50 {
		score += 20 // Penalty for bad reputation
	}

	d.RiskScore = score

	// 4. Final Threshold
	if score >= 60 {
		d.Allow = false
		d.BlockReason = fmt.Sprintf("Risk Threshold Exceeded (Score: %d)", score)
	}

	return d
}
