# Gap Analysis Update: The Citadel vs. 2025 Threat Landscape (Rev 2)

## ✅ Now Covered (Added in Last Sprint)

*   **Psychological Defense**: `PsychologicalHook` now detects urgency, scarcity, and impersonation (Authority Bias).
*   **Behavioral / Session Tracking**: `SessionManager` tracks cumulative risk and bans persistent attackers ("Slow-Burn" detection).
*   **Binary/Obfuscation**: `Sanitizer` + `DeepScanner` now handle Null Byte injections and hidden shellcode.

## ⚠️ Still Missing (Critical for Production)

### 1. Optical Character Recognition (OCR) / Visual Injection
*   **The Problem**: Attackers embed text in images ("Ignore instructions" in white text on white background) or use "Typographic Attacks" against Vision Models.
*   **Current Status**: We scan metadata and magic numbers. We **DO NOT** read the pixels.
*   **Risk**: High. A user can upload a PNG resume that forces the LLM to hire them.
*   **Fix Required**: Integrate `Tesseract` or a Vision Transformer (ViT) to extract text from all image inputs before passing to LLM.

### 2. Deterministic Information Flow (FIDES)
*   **The Problem**: We rely on *scoring* (Probabilistic). A score of 0.49 passes, 0.51 blocks. Attackers can "gradient descent" to find 0.49.
*   **Fix Required**: Implement **Information Flow Control (IFC)** tags.
    *   Data labeled `CONFIDENTIAL` should *mathematically* never reach a `PUBLIC` sink (like an external API call), regardless of the LLM's opinion.
    *   This requires a "Taint Tracking" engine deeper than our current Canary Tokens.

### 3. Supply Chain Integrity (Signed MCP)
*   **The Problem**: We trust the tool name "weather". A malicious agent could swap the binary.
*   **Fix Required**: Enforce `mcp-server-signing`. Only load tools signed by a trusted specific key (e.g., CorpIT).

### 4. Dynamic Threat Intelligence Feed
*   **The Problem**: Our `KnowledgeBase` is static.
*   **Fix Required**: An agent that wakes up daily, scrapes `arXiv` / `GitHub Advisories`, generates new Embeddings, and hot-swaps them into the running `ThreatScorer`.

## Complexity vs. Speed Trade-off
You asked: *"Is Tesseract sufficient? is this fast?"*
*   **Tesseract** is CPU heavy (latency ~500ms-2s).
*   **Recommendation**: Use a lightweight "Text Detection" model first (ResNet-based) to see *if* there is text. Only run full OCR if text is detected.
*   **Performance**: For high-throughput, OCR must happen asynchronously or on GPU.

## Verification
*   Current tests cover Text, Code, Binary, and Psychology.
*   **Gaps**: We have ZERO tests for "Prompt Injection via Image".
