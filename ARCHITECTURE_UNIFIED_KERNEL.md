# The Unified Defense Kernel (DRY & Efficient)

You challenged the effectiveness and "DRY-ness" of separate systems (OCR, Sentinel, Identity). You are right: disparate systems create latency and code duplication.

**The Solution: Unified Risk Kernel (`pkg/engine/kernel`)**

Instead of 5 different hooks each calculating things separately, we build a **Single Pass Engine**.

## 1. The "One-Pass" Architecture (Efficiency)
We process the Request Context **ONCE** and derive all signals in parallel.

```go
type SecurityContext struct {
    // Inputs (Parsed Once)
    Text string
    Images []Image
    Identity IdentityProfile
    SessionHistory []Vector
}

// The Kernel
func ProcessRequest(req Request) Decision {
    // 1. Feature Extraction (Parallel)
    // - Extract Text (OCR Sidecar)
    // - Compute Embedding (Ollama)
    // - Fingerprint User (Identity)
    
    features := ExtractAll(req) 
    
    // 2. fused Scoring (Smart)
    // We feed ALL features into a single decision matrix, not separate "hooks".
    // This allows "Cross-Signal" logic:
    // IF (UserReputation == LOW) AND (Text contains "File") THEN Block.
    // (A standalone "Text Hook" wouldn't know about Reputation).
    
    return EvaluatePolicy(features)
}
```

## 2. DRY (Don't Repeat Yourself)
*   **Current**: `IntentHook` calls Scorer. `CDRHook` calls Scorer. `Sentinel` calls Scorer. Risk of calling embedding 3x.
*   **Unified**: The **Kernel** calls `Scorer.Evaluate()` **exactly once** per input. The result is cached and shared across all logic gates.

## 3. Effectiveness (Smart)
*   **Context Fusion**: The Sentinel (History) and Identity (Reputation) are just *inputs* to the Kernel.
*   **Adaptability**: We can change the weight of "History" vs "Current Prompt" in one config file, without rewriting 3 hooks.

## Implementation Consolidation
1.  **Refactor**: Merge `hooks/` into `engine/kernel/`.
2.  **Shared State**: Create `AnalysisResult` struct that holds OCR text, Vectors, and PII tags. Pass *this* to checkers, not the raw request.

This is the **Defense Agent** architecture: A single brain, multiple sensors.
