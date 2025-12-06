#!/bin/bash
# Citadel Vision Sidecar Launcher
# Reliable setup using 'uv' and local virtual environment.

echo "=== 🚀 Citadel Vision Sidecar Launcher ==="

# Navigate to service directory
if [ -d "services/vision" ]; then
    cd services/vision
fi

# Ensure requirements.txt exists here
if [ ! -f "requirements.txt" ]; then
    echo "❌ Error: requirements.txt not found in $(pwd)"
    exit 1
fi

# Check for 'uv'
if ! command -v uv &> /dev/null; then
    echo "⚠️  'uv' not found. Please install it: curl -LsSf https://astral.sh/uv/install.sh | sh"
    echo "Falling back to standard python3 venv..."
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    python3 -m spacy download en_core_web_lg
    python3 main.py
    exit 0
fi

# Use UV
echo "⚡ Using 'uv' for dependency management..."

if [ ! -d ".venv" ]; then
    echo "📦 Creating virtual environment (.venv)..."
    uv venv
fi

# Activate
source .venv/bin/activate

# Install
echo "📦 Syncing dependencies..."
uv pip install -r requirements.txt
uv pip install pip # Ensure pip exists for Spacy downloader

# Download Spacy Model
if ! python3 -c "import spacy; spacy.load('en_core_web_lg')" &> /dev/null; then
    echo "🧠 Downloading Spacy NLP Model (en_core_web_lg)..."
    python3 -m spacy download en_core_web_lg
fi

echo "🟢 Starting Python Service..."
python3 main.py
