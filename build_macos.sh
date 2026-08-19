#!/usr/bin/env bash
# ============================================
#   📦 Build AegisScan — macOS
#   Cách dùng:  ./build_macos.sh
#   Tùy chọn:   BUILD_MODE=onefile (1 file) | onedir (thư mục, mặc định)
# ============================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Kích hoạt venv nếu có
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

echo "============================================"
echo "   Đóng gói AegisScan (macOS)"
echo "============================================"
echo "Python: $(python --version 2>&1)"

# Cài PyInstaller
python -m pip install pyinstaller -q
echo "✅ PyInstaller sẵn sàng"

# Cấu hình
BROWSERS_SRC="${PLAYWRIGHT_BROWSERS_SRC:-$HOME/Library/Caches/ms-playwright}"
BUILD_MODE="${BUILD_MODE:-onedir}"

if [ ! -d "$BROWSERS_SRC" ]; then
    echo "❌ Không tìm thấy Playwright browsers tại: $BROWSERS_SRC"
    echo "   Chạy trước:  python -m playwright install chromium"
    exit 1
fi

echo "🌐 Playwright browsers: $BROWSERS_SRC"
echo "📁 Chế độ build: $BUILD_MODE"

# Build
cd smart_scanner
export PLAYWRIGHT_BROWSERS_SRC
export BUILD_MODE
python -m PyInstaller packaging/smart_scanner.spec --noconfirm --clean

echo ""
echo "============================================"
echo "✅ HOÀN TẤT! Ứng dụng tại:"
echo "   smart_scanner/dist/AegisScan/"
echo ""
echo "Chạy:  dist/AegisScan/AegisScan"
echo "Mở browser tại: http://127.0.0.1:8501"
echo "============================================"
