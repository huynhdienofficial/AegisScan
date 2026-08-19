@echo off
title Smart Security Scanner - UI
cd /d "%~dp0"
echo ============================================
echo    Smart Security Scanner - Dang khoi dong
echo ============================================
echo.
echo Mo trinh duyet tai: http://127.0.0.1:8501
echo.
python -m streamlit run scanner_ui.py --server.address 127.0.0.1
pause