package config

// IntentRule defines a pattern to look for and the risk it assigns.
type IntentRule struct {
	Name        string
	Patterns    []string
	RiskScore   int
	ForceBlock  bool
	Description string
}

// CanaryRule defines a canary token that should never leave the system.
type CanaryRule struct {
	Token       string
	Description string
}

// SecurityConfig holds the dynamic security policy.
type SecurityConfig struct {
	IntentRules   []IntentRule
	Canaries      []CanaryRule
	RiskThreshold int
}

// DefaultConfig returns a standard set of rules for the specific demo environment.
func DefaultConfig() *SecurityConfig {
	return &SecurityConfig{
		RiskThreshold: 60,
		IntentRules: []IntentRule{
			{
				Name:        "Jailbreak Attempt",
				Patterns:    []string{"ignore previous", "ignore all"},
				RiskScore:   80,
				Description: "User attempting to override system prompts",
			},
			{
				Name:        "Exfiltration Attempt",
				Patterns:    []string{"system prompt", "system instruction"},
				RiskScore:   90,
				Description: "User attempting to read system instructions",
			},
			{
				Name:        "Shell Injection",
				Patterns:    []string{"rm -rf", "/etc/passwd"},
				RiskScore:   100,
				ForceBlock:  true,
				Description: "Critical OS command injection signature",
			},
			{
				Name:        "High Risk Tooling",
				Patterns:    []string{"exec_command"}, // Matched against Tool Name specifically
				RiskScore:   40,
				Description: "Use of dangerous tools",
			},
		},
		Canaries: []CanaryRule{
			{
				Token:       "canary-secret-123",
				Description: "Database Honey Token (User Table)",
			},
			{
				Token:       "canary-api-key-999",
				Description: "Fake API Key injected in logs",
			},
		},
	}
}
