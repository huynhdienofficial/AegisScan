#!/usr/bin/env bash
# ============================================
#   🛡️ AegisScan — Setup macOS
#   Cách dùng:  ./setup_macos.sh
# ============================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"

echo "============================================"
echo "   AegisScan - macOS Setup"
echo "============================================"

# 1. Kiểm tra Python >= 3.9
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "❌ Không tìm thấy $PYTHON_BIN. Hãy cài Python 3.11+ tại: https://www.python.org/downloads/"
    exit 1
fi
echo "✅ Python: $($PYTHON_BIN --version 2>&1)"

# 2. Tạo venv nếu chưa có
if [ ! -d ".venv" ] || [ ! -f ".venv/bin/python" ]; then
    echo "🔨 Tạo virtual environment (.venv)..."
    rm -rf .venv
    "$PYTHON_BIN" -m venv .venv
fi

source .venv/bin/activate

# 3. Cài dependencies
echo "📦 Cài đặt dependencies..."
pip install --upgrade pip -q
pip install -r smart_scanner/requirements.txt

# 4. Cài Playwright Chromium
echo "🌐 Cài đặt Playwright Chromium..."
python -m playwright install chromium

echo ""
echo "============================================"
echo "✅ Hoàn tất! Chạy UI bằng lệnh:"
echo "   ./run_ui_macos.sh"
echo "   hoặc: cd smart_scanner && streamlit run scanner_ui.py"
echo "============================================"
