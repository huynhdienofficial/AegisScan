#!/usr/bin/env bash
# ============================================
#   🚀 AegisScan — Chạy UI macOS
#   Cách dùng:  ./run_ui_macos.sh
# ============================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Kích hoạt venv
if [ -d ".venv" ] && [ -f ".venv/bin/python" ]; then
    source .venv/bin/activate
else
    echo "❌ Chưa có môi trường Python. Chạy trước: ./setup_macos.sh"
    exit 1
fi

cd smart_scanner
echo "============================================"
echo "   AegisScan - Đang khởi động"
echo "============================================"
echo "Mở trình duyệt tại: http://127.0.0.1:8501"
echo "--------------------------------------------"
# Chỉ bind localhost (bảo mật — xem data_residency.py #64)
# --server.headless true: bỏ qua prompt onboarding "Email" lần chạy đầu tiên
streamlit run scanner_ui.py --server.address 127.0.0.1 --server.headless true
