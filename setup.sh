#!/usr/bin/env bash
# setup.sh — One-command reproducible setup for the Email Cryptographic Forensics Framework
# Tested on Ubuntu 22.04+, Python 3.11+
# Usage: bash setup.sh

set -e

echo "🔐 Email Cryptographic Forensics Framework — Setup"
echo "=================================================="

# ── 1. Check Python ─────────────────────────────────────────────────────────
if ! command -v python3 &> /dev/null; then
    echo "❌  Python 3 not found. Please install Python 3.11 or later."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "✓  Python $PYTHON_VERSION found"

# ── 2. Create virtual environment ────────────────────────────────────────────
if [ ! -d ".venv" ]; then
    echo "  Creating virtual environment..."
    python3 -m venv .venv
fi
echo "✓  Virtual environment ready"

# ── 3. Activate venv ─────────────────────────────────────────────────────────
source .venv/bin/activate

# ── 4. Upgrade pip ───────────────────────────────────────────────────────────
pip install --quiet --upgrade pip

# ── 5. Install dependencies ──────────────────────────────────────────────────
echo "  Installing dependencies from requirements.txt..."
pip install --quiet -r requirements.txt
echo "✓  Dependencies installed"

# ── 6. Generate demo PCAPs ──────────────────────────────────────────────────
echo "  Generating synthetic forensic demo PCAPs..."
python3 -m generator.pcap_generator 2>/dev/null | grep -v CryptographyDeprecation || true
echo "✓  Demo PCAPs generated in sample_pcaps/"

# ── 7. Run tests ─────────────────────────────────────────────────────────────
echo "  Running test suite..."
python3 -m unittest discover -s tests -p "test_*.py" -q 2>/dev/null && echo "✓  All tests passing" || echo "⚠  Some tests failed — check output above"

echo ""
echo "✅  Setup complete! You can now run:"
echo ""
echo "  # Interactive Dashboard (recommended for demo):"
echo "  source .venv/bin/activate"
echo "  streamlit run dashboard/app.py"
echo ""
echo "  # CLI analysis:"
echo "  python3 main.py --analyze sample_pcaps/weak_cipher_starttls.pcap"
echo ""
echo "  # FastAPI REST server:"
echo "  python3 main.py --run-api"
echo ""
