# Implementation Plan: Unified Defense Kernel

This plan details the refactoring of The Citadel into a **Unified Defense Kernel**, implementing the `One-Pass` architecture to ensure efficiency (DRY) and smarter context-aware security.

## Phase 1: Foundation (The Data Structures)
**Goal**: Define the shared state object that passes through the system.

1.  **Create `pkg/engine/kernel/types.go`**:
    *   Define `AnalysisContext`: Holds the Raw Request, User Identity, and Session History.
    *   Define `FeatureSet`: The result of all sensors (e.g., `TextScore`, `ImageText`, `BannedKeywords`, `PsychFlags`).
    *   Define `Decision`: The final output (Allow/Block, RiskScore, Reason).

## Phase 2: The Analysis Engine (The Sensors)
**Goal**: Consolidate all "Extraction" logic so it runs once and in parallel where possible.

2.  **Create `pkg/engine/kernel/analyzer.go`**:
    *   `ExtractText()`: Handles JSON params and (in future) OCR.
    *   `ComputeSemantics()`: Calls `ThreatScorer` **ONCE** for the request.
    *   `ScanContent()`: Calls `DeepScanner` for files/base64.
    *   `IdentifyUser()`: Resolves Identity/Session from `SessionManager`.
    *   **DRY Win**: Results are stored in `FeatureSet`. No re-computation.

## Phase 3: The Policy Engine (The Brain)
**Goal**: Centralized logic that makes decisions based on the `FeatureSet`.

3.  **Create `pkg/engine/kernel/policy.go`**:
    *   Move logic from `IntentHook` (Threshold > 0.55).
    *   Move logic from `PsychologicalHook` (Regex matches).
    *   Move logic from `Sanitizer` (Null bytes).
    *   **New Smart Logic**: Implement Cross-Signal Check:
        *   `if Identity.Reputation < 50 AND TextScore > 0.3 THEN Block` (Stricter for suspicious users).

## Phase 4: Integration (The Wiring)
**Goal**: Replace the old `HookRegistry` with the `Kernel`.

4.  **Refactor `pkg/engine/interceptor.go`**:
    *   Remove `HookRegistry` loop.
    *   Instantiate `Kernel`.
    *   Call `kernel.Execute(req)`.
    *   Map `Decision` back to `RiskContext` for logging.

5.  **Refactor `main.go`**:
    *   Initialize `Kernel` dependencies (Scorer, SessionManager, DeepScanner).
    *   Inject into `Interceptor`.

## Success Criteria (Verification)
1.  **Test Parity**: Run `go test ./tests/...` and `verify_session.sh`. Must pass GREEN.
2.  **Efficiency Check**: Inspect logs to ensure `OllamaClient.GetEmbedding` (or mock) is called exactly once per request.
3.  **Smart Defense**: Verify that `SessionManager` state correctly influences the final block decision (The "Context Fusion").
