@echo off
title Smart Security Scanner - Build Windows
rem ============================================
rem   Build Smart Security Scanner - Windows
rem   Cach dung:  build_windows.bat
rem   Tuy chon:  set BUILD_MODE=onefile  (1 file) | onedir (mac dinh)
rem ============================================
cd /d "%~dp0"

echo ============================================
echo    Dong goi Smart Security Scanner (Windows)
echo ============================================

python --version
python -m pip install pyinstaller -q
if errorlevel 1 goto :error
echo OK: PyInstaller san sang

rem Cau hinh
if "%BROWSERS_SRC%"=="" set BROWSERS_SRC=%USERPROFILE%\AppData\Local\ms-playwright
if "%BUILD_MODE%"=="" set BUILD_MODE=onedir

if not exist "%BROWSERS_SRC%" (
    echo LOI: Khong tim thay Playwright browsers tai: %BROWSERS_SRC%
    echo Chay truoc:  python -m playwright install chromium
    goto :error
)

echo Playwright browsers: %BROWSERS_SRC%
echo Che do build: %BUILD_MODE%

cd smart_scanner
set PLAYWRIGHT_BROWSERS_SRC=%BROWSERS_SRC%
set BUILD_MODE=%BUILD_MODE%
python -m PyInstaller packaging\smart_scanner.spec --noconfirm --clean
if errorlevel 1 goto :error

echo.
echo ============================================
echo    HOAN TAT! Ung dung tai:
echo    smart_scanner\dist\SmartSecurityScanner\
echo.
echo    Chay:  dist\SmartSecurityScanner\SmartSecurityScanner.exe
echo    Mo browser tai: http://127.0.0.1:8501
echo ============================================
pause
exit /b 0

:error
echo.
echo LOI XAY RA! Xem chi tiet o tren.
pause
exit /b 1
