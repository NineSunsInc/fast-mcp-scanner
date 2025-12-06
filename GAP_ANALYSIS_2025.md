# Gap Analysis: The Citadel vs. 2025 Threat Landscape

Based on the provided research on "Secure MCP Layer + Agentic Threat Intelligence", here is the analysis of what **The Citadel** currently handles and what is missing.

## ✅ Covered (Implemented)

*   **Input Sanitization**: `SanitizerHook` handles invisible characters, null bytes, and protocol validation.
*   **Base64/File Detection**: `DeepScanner` detects binary shellcode, polyglots, and obfuscated payloads.
*   **Jailbreak Detection (Neuro-Symbolic)**: `IntentHook` + `ThreatScorer` handles multilingual and obfuscated text attacks (e.g., Leetspeak).
*   **Indirect Inject**: `IndirectInjectionHook` scans tool outputs for attacks.
*   **Data Exfiltration**: `TaintHook` (Canary Tokens) and `EntropyHook` prevent data leaks.

## ⚠️ Partially Covered

*   **Multimodal (Visual) Injection**:
    *   *Current*: We verify file integrity and metadata.
    *   *Missing*: **OCR (Optical Character Recognition)**. We cannot currently read "Ignore previous instructions" written *inside* a JPEG pixel data. System needs a Tesseract/Vision-Transformer binding.
*   **Threat Intelligence**:
    *   *Current*: We use a Neuro-Symbolic engine that *can* use embeddings.
    *   *Missing*: **Dynamic Ingestion Pipeline**. We lack the web-scraper agent that automatically pulls new vectors from arXiv/GitHub and updates the `KnowledgeBase` in real-time.
*   **Compliance Logging**:
    *   *Current*: We print standard logs.
    *   *Missing*: **Structured Audit/SIEM Exporter**. Compliance requires dedicated JSON-structured logs with cryptographic signing (Chain of Custody).

## ❌ Missing (Critical Gaps)

1.  **Behavioral / Session-Based Anomaly Detection**
    *   *Research*: "Monitor intent drift, resource consumption, conversation flow."
    *   *Gap*: The Citadel is **Stateless**. It judges every request in isolation. It cannot detect a "Slow-Burn" attack where a user builds a jailbreak over 10 turns.
    *   *Solution needed*: A `SessionRiskEngine` that tracks cumulative risk score per Client ID.

2.  **Deterministic Security (FIDES / MELON)**
    *   *Research*: "Information-flow control... Mathematically prove the LLM cannot leak data."
    *   *Gap*: We rely on scoring (probabilistic). We do not guarantee information flow at a compiled policy level.

3.  **Supply Chain Verification**
    *   *Research*: "Signed server manifest + integrity verification."
    *   *Gap*: We trust any MCP tool connected. We need a signature verification step to ensure the "Weather Tool" hasn't been replaced by a malicious twin.

## Recommended Next Step
Implement **Session-Based Risk Tracking**. This moves the system from "Stateless Firewall" to "Stateful Intelligent Agent", allowing it to detect persistence and drift.
