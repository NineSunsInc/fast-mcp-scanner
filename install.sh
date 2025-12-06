#!/bin/bash
set -e

# Citadel "One-Click" Installer
# 1. Builds Binary
# 2. Sets up Vision Sidecar
# 3. Generates Configuration

echo "🛡️  Installing Citadel Security Gateway..."

# 1. Check Prerequisites
if ! command -v go &> /dev/null; then
    echo "❌ Error: 'go' is not installed."
    exit 1
fi

# 2. Build Citadel
echo "🏗️  Building Citadel Binary..."
go build -o citadel cmd/gateway/main.go
echo "✅ Binary built: $(pwd)/citadel"

# 3. Setup Python Sidecar
echo "🐍 Setting up Vision Sidecar (PaddleOCR + Presidio)..."
if ! command -v uv &> /dev/null; then
    echo "⚠️  'uv' not found. Installing it for faster setup..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    source $HOME/.cargo/env 2>/dev/null || true
fi

# Force run the vision launcher's setup (headless)
cd services/vision
if [ ! -d ".venv" ]; then
    uv venv
fi
source .venv/bin/activate
uv pip install -r requirements.txt
uv pip install pip
# Pre-download models to avoid runtime delay
python3 -c "import spacy; spacy.load('en_core_web_lg') or spacy.download('en_core_web_lg')" 2>/dev/null || python3 -m spacy download en_core_web_lg
cd ../..

echo "✅ Vision Engine Ready."

# 4. Generate Config Snippet
ABS_PATH=$(pwd)
NPX_PATH=$(which npx)

echo "
============================================================
🎉 INSTALLATION COMPLETE!
============================================================

To use Citadel with Claude Desktop, edit your config file:
  Mac: ~/Library/Application Support/Claude/claude_desktop_config.json

Add this to 'mcpServers':

\"secure-filesystem\": {
  \"command\": \"$ABS_PATH/citadel\",
  \"args\": [
    \"--proxy\",
    \"$NPX_PATH\",
    \"-y\",
    \"@modelcontextprotocol/server-filesystem\",
    \"$HOME/Desktop\"
  ]
}

Then restart Claude and run './run_vision.sh' in a terminal.
============================================================
"
