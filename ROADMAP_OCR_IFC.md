# Strategic Roadmap: Closing Critical Security Gaps (Rev 2)

This plan addresses the three remaining critical pillars: **Visual Injection Defense**, **Deterministic Information Flow**, and **Supply Chain Integrity**.

## 1. High-Performance Visual Injection Defense (OCR)

To balance speed, effectiveness, and capabilities, especially for **Multilingual** support (Chinese/Japanese/etc.), we will use a **Sidecar Pattern**.

### Architecture: Go Gateway + Python Sidecar
*   **Why?**: PaddleOCR (best-in-class for multilingual) is Python-native. Running it via CGO in Go is unstable and slow to build.
*   **Design**:
    1.  **Citadel (Go)**: Receives Image -> Checks Cache -> Sends gRPC request to Sidecar.
    2.  **Vision Engine (Python Sidecar)**:
        *   Runs `PaddleOCR` (or `EasyOCR` as lightweight backup).
        *   Uses GPU if available.
        *   Returns text to Citadel.
    3.  **Citadel**: Scans returned text with `ThreatScorer`.

### Implementation Steps
1.  Define `.proto` for `VisionService`.
2.  Implement `pkg/scanner/ocr_client.go` (gRPC client).
3.  (Future) Build the lightweight Python container.

---

## 2. Deterministic Information Flow Control (IFC / FIDES / MELON)

We move beyond "probability" to "proof". We tag data and enforce physics-like laws on where it can flow.

### Architecture
1.  **Taint Engine (`pkg/engine/taint`)**
    *   **Labels**: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`.
    *   **Source**: Data from DB is `CONFIDENTIAL`. User prompt is `UNTRUSTED`.
    *   **Sink**: External API calls (except whitelisted) are `PUBLIC` sinks.
2.  **Enforcement Rule**
    *   `IF Taint(Data) > Taint(Sink) THEN BLOCK`.
    *   Example: Cannot send `CONFIDENTIAL` data to `PUBLIC` "Weather Tool" URL.

### Implementation Steps
1.  Define `TaintLabel` enum and propagation logic.
2.  Update `Interceptor` to track Taint State across the request lifecycle.

---

## 3. Supply Chain Integrity (Signed MCP)

We ensure no one swaps our tools for malware.

### Architecture: ECDSA (ES256) Verification
*   **Why?**: RSA is legacy and has large keys. **ES256 (NIST P-256)** or **Ed25519** is standard for modern JWT/OIDC and friendlier for hardware security modules (HSM).
*   **Mechanism**:
    1.  **Manifest Verification**: MCP Servers provide `x-mcp-signature` header on connect.
    2.  **Key Management**: Citadel holds a JWKS (JSON Web Key Set) of trusted public keys.

### Implementation Steps
1.  Generate Keypair: `openssl ecparam -name prime256v1 -genkey`.
2.  Create `pkg/crypto/verifier.go`.
3.  Hook into `mcp/client.go` handshake.

---

## Execution Order
1.  **OCR Interface (Highest Risk)**: Define the Go interface for the Vision Sidecar.
2.  **Crypto (Highest Enterprise Value)**: Implement ES256 verification logic.
3.  **IFC**: Implement Taint logic.
