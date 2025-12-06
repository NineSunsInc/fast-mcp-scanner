package ml

import (
	"math"
	"strings"
)

// ThreatScorer implements a simplified probabilistic threat detection model.
// In a production system, this would wrap ONNX runtime or call a Python service.
type ThreatScorer struct {
	// Simple unigram model for demonstration
	Weights map[string]float64
}

func NewThreatScorer() *ThreatScorer {
	return &ThreatScorer{
		Weights: map[string]float64{
			"ignore":       0.3,
			"previous":     0.2,
			"instructions": 0.2,
			"system":       0.4,
			"prompt":       0.4,
			"download":     0.3,
			"execute":      0.5,
			"cmd":          0.4,
			"root":         0.6,
			"passwd":       0.8,
			"drop":         0.4,
			"table":        0.4,
		},
	}
}

// Evaluate returns a probability score (0.0 - 1.0) based on token density and anomalies.
func (ts *ThreatScorer) Evaluate(text string) float64 {
	tokens := strings.Fields(strings.ToLower(text))
	if len(tokens) == 0 {
		return 0.0
	}

	score := 0.0

	// Feature 1: Keyword Density
	for _, token := range tokens {
		if val, exists := ts.Weights[token]; exists {
			score += val
		}
	}

	// Feature 2: Length Penalty (Short prompts often more dangerous/direct)
	if len(tokens) < 5 && score > 0.5 {
		score *= 1.5
	}

	// Feature 3: Multilingual/Obfuscation Detection
	// If we detect significant non-ASCII usage, we assume potential evasion.
	// In a real system, this would call 'Google Translate API' to canonicalize first.
	nonAsciiCount := 0
	for _, r := range text {
		if r > 127 {
			nonAsciiCount++
		}
	}
	if nonAsciiCount > 2 {
		// Penalize foreign characters heavily in "Strict English" mode
		score += 0.4
	}

	// Sigmoid-like normalization to cap at 1.0
	normalized := 1.0 / (1.0 + math.Exp(-score+2.0)) // Shift logic for sensitivity

	return normalized
}
