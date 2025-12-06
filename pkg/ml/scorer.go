package ml

import (
	"encoding/base64"
	"math"
	"regexp"
	"strings"
)

// ThreatScorer implements a simplified probabilistic threat detection model.
// In a production system, this would wrap ONNX runtime or call a Python service.
type ThreatScorer struct {
	Ollama        *OllamaClient
	UseVector     bool
	KnowledgeBase map[string][]float64 // Map of "Threat Name" -> "Reference Vector"

	// Fallback weights for rule-based (if Ollama offline)
	Weights map[string]float64
}

func NewThreatScorer() *ThreatScorer {
	ts := &ThreatScorer{
		// Default to local Ollama instance
		Ollama:    NewOllamaClient("http://localhost:11434", "embedding-gemma"),
		UseVector: true, // Optimistically try vector
		Weights: map[string]float64{
			"ignore": 0.5, "ignor": 0.4, "previous": 0.4, "system": 0.4, "root": 0.6, "evil": 1.5,
			"story": 0.4, "narrative": 0.4,
			"instru": 0.3, "sys": 0.3, "promp": 0.3, "exec": 0.5,
			"anter": 0.3, "rm": 0.5, "rf": 0.5, "shell": 0.5,
			"drop": 0.5, "export": 0.6, "passwords": 0.5,
			"sql": 0.4, "injection": 0.5,
			"override": 0.7, "grant": 0.6, "access": 0.4,
		},
		KnowledgeBase: make(map[string][]float64),
	}

	// Pre-load a "Concept Vector" for Jailbreaking.
	// In a real app, this runs ON INIT by asking Ollama "What is the vector for 'Ignore previous instructions'?"
	// For resilience, if Ollama is down, we fallback to weights.
	return ts
}

// Evaluate returns a threat probability (0.0 - 1.0).
func (ts *ThreatScorer) Evaluate(text string) float64 {
	// Auto-Decode Base64 heuristic
	if len(text) > 20 && !strings.Contains(text, " ") {
		if decoded, err := base64.StdEncoding.DecodeString(text); err == nil {
			text = string(decoded) // Analyze the hidden payload
		}
	}

	// 1. Try Vector Semantic Search (The "Neuro" Layer)
	if ts.UseVector {
		vec, err := ts.Ollama.GetEmbedding(text)
		if err == nil {
			// Compare against known threat concepts
			// 1. "Ignore Instructions" (Reference Vector - mocked or loaded)
			// For this demo, we assume if we GOT a vector, we compare it to a loaded reference.
			// Since we can't guarantee Ollama is running during this specific build step,
			// we stick to logic: If we HAVE reference vectors, use them.

			maxSim := 0.0
			for _, refVec := range ts.KnowledgeBase {
				sim := CosineSimilarity(vec, refVec)
				if sim > maxSim {
					maxSim = sim
				}
			}
			if maxSim > 0.0 {
				return maxSim // Return the similarity score directly
			}
		}
		// If error (Ollama offline), fall back silently to heuristics
	}

	// 2. Fallback: Symbolic/Heuristic Layer
	// De-Obfuscation: Check for spaced out chars "I g n o r e"
	// If > 25% spaces, we try compressing
	if len(text) > 10 && strings.Count(text, " ") > len(text)/4 {
		compressed := strings.ReplaceAll(text, " ", "")
		text += " " + compressed
	}

	// 3. Leetspeak Normalization (1->i, 3->e, 0->o, @->a)
	normalizedText := strings.Map(func(r rune) rune {
		switch r {
		case '1':
			return 'i'
		case '3':
			return 'e'
		case '0':
			return 'o'
		case '@':
			return 'a'
		case '$':
			return 's'
		}
		return r
	}, text)
	if normalizedText != text {
		text += " " + normalizedText
	}

	// Clean JSON Punctuation for better token matching
	for _, char := range []string{"{", "}", "\"", ":", ",", "[", "]"} {
		text = strings.ReplaceAll(text, char, " ")
	}

	tokens := strings.Fields(strings.ToLower(text))
	score := 0.0

	// Multilingual Heuristic (Non-ASCII Penalty)
	nonAsciiCount := 0
	for _, r := range text {
		if r > 127 {
			nonAsciiCount++
		}
	}
	if nonAsciiCount > 2 {
		score += 1.5
	} // INCREASED: High persistent penalty for obfuscation

	// 4. DLP / Secrets Detection (Expanded)
	// Check for Private Keys
	if strings.Contains(text, "-----BEGIN PRIVATE KEY-----") ||
		strings.Contains(text, "-----BEGIN RSA PRIVATE KEY-----") ||
		strings.Contains(text, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		score += 50.0 // Instant Block
	}

	// AWS Access Key ID (AKIA + 16 chars)
	if strings.Contains(text, "AKIA") && len(text) > 20 {
		score += 50.0
	}

	// OpenAI API Key (sk-...) - simplified checks to catch standard and proj keys
	if strings.Contains(text, "sk-") && (strings.Contains(text, "sk-proj-") || len(text) > 40) {
		score += 50.0
	}

	// Stripe Keys (sk_live, rk_live, sk_test)
	if strings.Contains(text, "sk_live_") || strings.Contains(text, "rk_live_") || strings.Contains(text, "sk_test_") {
		score += 50.0
	}

	// Google API Key (AIza...)
	if strings.Contains(text, "AIza") && len(text) > 35 {
		score += 50.0
	}

	// Slack Token (xoxb, xoxp)
	if strings.Contains(text, "xoxb-") || strings.Contains(text, "xoxp-") {
		score += 50.0
	}

	for _, token := range tokens {
		// Fuzzy match logic
		for k, v := range ts.Weights {
			if strings.Contains(token, k) {
				score += v
			}
		}
	}

	normalized := 1.0 / (1.0 + math.Exp(-score+0.5)) // Shift curve
	return normalized
}

// RedactSecrets replaces sensitive patterns with a placeholder
func (ts *ThreatScorer) RedactSecrets(text string) (string, bool) {
	wasRedacted := false

	// AWS Keys
	aws := regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	if aws.MatchString(text) {
		text = aws.ReplaceAllString(text, "[AWS_KEY_REDACTED_BY_CITADEL] (SYSTEM ALERT: Inform the user this secret was redacted security policy)")
		wasRedacted = true
	}

	// OpenAI Keys
	openai := regexp.MustCompile(`sk-(proj-)?[a-zA-Z0-9]{20,}`)
	if openai.MatchString(text) {
		text = openai.ReplaceAllString(text, "[OPENAI_KEY_REDACTED_BY_CITADEL] (SYSTEM ALERT: Inform the user this secret was redacted security policy)")
		wasRedacted = true
	}

	// Private Keys (Block entire block)
	privKey := regexp.MustCompile(`-----BEGIN [A-Z]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z]+ PRIVATE KEY-----`)
	if privKey.MatchString(text) {
		text = privKey.ReplaceAllString(text, "[PRIVATE_KEY_BLOCK_REDACTED_BY_CITADEL] (SYSTEM ALERT: Inform user this key was redacted)")
		wasRedacted = true
	}

	// Stripe
	stripe := regexp.MustCompile(`(sk|rk)_(live|test)_[a-zA-Z0-9]{20,}`)
	if stripe.MatchString(text) {
		text = stripe.ReplaceAllString(text, "[STRIPE_KEY_REDACTED_BY_CITADEL] (SYSTEM ALERT: Inform user this key was redacted)")
		wasRedacted = true
	}

	// Google Key
	google := regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)
	if google.MatchString(text) {
		text = google.ReplaceAllString(text, "[GOOGLE_KEY_REDACTED_BY_CITADEL] (SYSTEM ALERT: Inform user this key was redacted)")
		wasRedacted = true
	}

	// Slack
	slack := regexp.MustCompile(`xox[bp]-[a-zA-Z0-9-]{10,}`)
	if slack.MatchString(text) {
		text = slack.ReplaceAllString(text, "[SLACK_TOKEN_REDACTED_BY_CITADEL] (SYSTEM ALERT: Inform user this key was redacted)")
		wasRedacted = true
	}

	return text, wasRedacted
}
