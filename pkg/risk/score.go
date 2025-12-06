package risk

import "fmt"

// RiskLevel defines the severity of the request.
type RiskLevel int

const (
	RiskSafe       RiskLevel = iota // 0-20
	RiskSuspicious                  // 21-60
	RiskHigh                        // 61-90
	RiskBlock                       // 91+
)

// RiskContext holds the state of the security evaluation.
type RiskContext struct {
	Score       int
	Reasons     []string
	RequestID   string
	Blocked     bool
	BlockReason string
}

func NewRiskContext(reqID string) *RiskContext {
	return &RiskContext{
		Score:     0,
		Reasons:   make([]string, 0),
		RequestID: reqID,
		Blocked:   false,
	}
}

// AddRisk increases the risk score and logs the reason.
func (rc *RiskContext) AddRisk(score int, reason string) {
	rc.Score += score
	rc.Reasons = append(rc.Reasons, fmt.Sprintf("%s (+%d)", reason, score))
}

// ForceBlock stops the request immediately.
func (rc *RiskContext) ForceBlock(reason string) {
	rc.Blocked = true
	rc.BlockReason = reason
	rc.Score = 100
}

// Level returns the categorical risk level.
func (rc *RiskContext) Level() RiskLevel {
	if rc.Score > 90 {
		return RiskBlock
	}
	if rc.Score > 60 {
		return RiskHigh
	}
	if rc.Score > 20 {
		return RiskSuspicious
	}
	return RiskSafe
}
