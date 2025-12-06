# Global Identity Graph: Cross-Session Threat Tracking

You raised a critical point: **Attackers switch sessions.** If Session A is innocent and Session B is malicious, we need to link them.

## The Solution: Global Identity Intelligence (The "Graph")
We move beyond `SessionID` to `IdentityID`.

### 1. Identity Resolution (Fingerprinting)
We cannot rely on a fresh Session ID. We track the **User Entity** across sessions using:
*   **IP Address / Subnet**
*   **API Key / Auth Token** (if authenticated)
*   **Behavioral Fingerprint** (Typing patterns, vocabulary choice, tool usage patterns) -> *Advanced*
*   **Browser/Client Fingerprint** (User-Agent, JA3 TLS Hash)

### 2. The Global Risk Score
The `SessionManager` feeds into a `GlobalRiskEngine`.
*   `GlobalScore(User)` = `WeightedAverage(SessionA, SessionB, SessionC)`
*   **Scenario**:
    *   Session A: "Hello" (Risk 0) -> Ends.
    *   Session B: "Delete file" (Risk 90) -> Blocked.
    *   Session C: "Hello" -> **Formula**: Start Risk = `LowDecay(SessionB.Risk)`.
    *   *Result*: Session C starts with elevated scrutiny (e.g., Risk 40). The user burned their reputation in Session B.

### 3. Traceability & Forensics
Since we are building an MCP Gateway:
*   **Trace ID**: Every request gets a `trace_id` that is persisted forever (Log/DB).
*   **Graph Link**: `TraceID` -> `SessionID` -> `UserID`.
*   **Forensic Query**: "Show me all sessions for User X where they attempted File Deletion."

### Implementation Update
1.  **Upgrade `SessionManager`**: Rename to `IdentityManager`.
2.  **Key**: Map `SessionID` -> `IdentityKey` (e.g., hash of IP+Token).
3.  **Persistence**: Risk scores must live in Redis/DB (not just memory) to survive server restarts.

## Revised Architecture
```go
type IdentityProfile struct {
    IdentityKey     string
    GlobalReputation int // 0-100 (100 = Trusted, 0 = Banned)
    ActiveSessions  []string
    LastViolation   time.Time
}

func (im *IdentityManager) GetRisk(req *Request) int {
    key := fingerprint(req)
    profile := im.GetProfile(key)
    return profile.GlobalReputation
}
```
