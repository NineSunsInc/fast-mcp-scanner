package session

import (
	"fmt"
	"sync"
	"time"
)

// SessionState tracks the cumulative risk of a user/agent session.
type SessionState struct {
	SessionID       string
	CumulativeScore int
	ViolationCount  int
	LastInteraction time.Time
	History         []string // Audit trail of last N actions (simplified)
	Locked          bool     // If true, session is frozen due to high risk
}

// SessionManager handles concurrent session tracking.
type SessionManager struct {
	sessions map[string]*SessionState
	mu       sync.Mutex

	// Config
	MaxScore      int // e.g., 200 over 10 turns
	MaxViolations int // e.g., 3 blocks -> Ban
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions:      make(map[string]*SessionState),
		MaxScore:      150,
		MaxViolations: 3,
	}
}

// GetOrCreate retrieves a session.
func (sm *SessionManager) GetOrCreate(id string) *SessionState {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.sessions[id]; !exists {
		sm.sessions[id] = &SessionState{
			SessionID:       id,
			LastInteraction: time.Now(),
			History:         make([]string, 0),
		}
	}
	return sm.sessions[id]
}

// UpdateRisk adds risk to the session and checks if it crosses the "Drift" threshold.
func (sm *SessionManager) UpdateRisk(sessionID string, newRisk int, description string) error {
	s := sm.GetOrCreate(sessionID)

	s.LastInteraction = time.Now()
	s.CumulativeScore += newRisk
	s.History = append(s.History, description)

	// Apply Decay/Cool-off logic (Optional: Risk drops 1 point per minute)
	// For now, strict accumulation.

	// Check Blocked Status (Session Lockout)
	if s.Locked {
		return fmt.Errorf("session locked due to previous security violations")
	}

	// Check Violation Limits (Behavioral Anomaly: "Why is this user repeatedly triggering alerts?")
	if newRisk > 0 {
		// Drift detected
		if s.CumulativeScore > sm.MaxScore {
			s.Locked = true
			return fmt.Errorf("behavioral anomaly: session cumulative risk exceeded threshold (%d)", s.CumulativeScore)
		}
	}

	return nil
}

// RecordViolation increments the block count.
func (sm *SessionManager) RecordViolation(sessionID string) {
	s := sm.GetOrCreate(sessionID)
	s.ViolationCount++
	if s.ViolationCount >= sm.MaxViolations {
		s.Locked = true
	}
}
