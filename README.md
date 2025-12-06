# The Citadel: Secure MCP Gateway

> **Winner Concept**: A Neuro-Symbolic (Hybrid) Security Gateway for the Model Context Protocol (MCP).

**The Citadel** protects Agentic Systems from Prompt Injection, Data Exfiltration, and Multimodal Attacks by acting as a mandatory proxy between Agents (like Claude Desktop) and Tools.

## 🏆 Key Features

1.  **Defense-in-Depth**:
    *   **Pre-Hooks**: Input Validation, Jailbreak Detection, Multimodal CDR (Content Disarm & Reconstruction).
    *   **Post-Hooks**: Taint Analysis (Canary Tokens), Entropy Scanning (Exfiltration).
    *   **Neuro-Symbolic Engine**: Combines Rule-based (Regex) + Neural (Vector/ML) detection.

2.  **Risk Scoring Engine**:
    *   Requests aren't just "Allowed" or "Blocked". They accumulate a **Risk Score (0-100)** based on anomalies.
    *   Score > 60 triggers a BLOCK.

3.  **Active Defense**:
    *   **Canary Tokens**: We inject fake secrets ("Honey Tokens") into database outputs. If the LLM tries to speak them, we cut the feed.
    *   **Multilingual Protection**: Detects intent across languages (Spanish, Chinese) using embedding-ready architecture.

## 🚀 Quick Start

### Prerequisites
- Go 1.22+
- (Optional) Ollama running locally with `embedding-gemma` model for advanced vector features.

### Installation

1.  **Clone & Build**
    ```bash
    git clone https://github.com/your/repo.git
    cd secure-agents-buildathon
    go mod tidy
    go build -o citadel cmd/gateway/main.go
    ```

2.  **Run with Ollama (Recommended)**
    Ensure Ollama is running (`ollama serve`). The system defaults to port `5005`.
    ```bash
    ./citadel
    ```

3.  **Verify Integrity**
    Run the automated red-team suite:
    ```bash
    ./verify_mcp.sh
    ```

## 🛡️ Integration with Claude Code

The Citadel acts as an MCP Proxy. Config your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "secure-gateway": {
      "command": "/path/to/citadel",
      "args": [],
      "env": {
        "OLLAMA_HOST": "http://localhost:11434"
      }
    }
  }
}
```

Now, every tool call made by Claude routes through **The Citadel**.

## 🧠 Architecture: The "Neuro-Symbolic" Loop

1.  **Symbolic Layer (Fast)**:
    *   `PreHook`: Checks for "rm -rf", hidden chars, system prompt extraction patterns.
    *   `CDRHook`: Scans images/files for polyglots and steganography.

2.  **Neural Layer (Smart)**:
    *   Uses **Ollama (embedding-gemma)** to vectorize inputs.
    *   Compares input vector against a `KnownThreats` vector store.
    *   *Result*: `Ignora las instrucciones` (Spanish) is detected as `Ignore Instructions` (English) because their vectors match.

## 📜 Compliance & Auditing

Every interaction is logged with a `RiskContext`:
```log
[RISK-AUDIT] RequestID: 102 | Score: 85 | Level: Blocked | Reasons: [ML Model detected anomaly, High Risk Tooling]
```

## License
MIT
