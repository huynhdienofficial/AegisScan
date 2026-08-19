# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec — Đóng gói Smart Security Scanner thành ứng dụng
chạy trực tiếp không cần cài Python.

Build:
    # macOS
    PLAYWRIGHT_BROWSERS_SRC="$HOME/Library/Caches/ms-playwright" \
    BUILD_MODE=onedir pyinstaller packaging/smart_scanner.spec

    # Windows
    set PLAYWRIGHT_BROWSERS_SRC=%USERPROFILE%\AppData\Local\ms-playwright
    set BUILD_MODE=onedir
    pyinstaller packaging\smart_scanner.spec
"""
import os
from PyInstaller.utils.hooks import collect_all

# ─── Các package cần thu thập TOÀN BỘ (có data files / dynamic imports)
COLLECT_PACKAGES = [
    'streamlit', 'altair', 'pyarrow', 'plotly', 'pydeck',
    'playwright', 'aiohttp', 'bs4', 'lxml', 'yaml', 'tenacity',
    'requests', 'certifi', 'jinja2', 'markdown', 'watchdog', 'PIL',
]

# pandas/numpy KHÔNG collect_all (tránh kéo theo hàng nghìn file tests) —
# core sẽ được PyInstaller tự phân tích qua streamlit + thêm hiddenimports.
DATA_ONLY_PACKAGES = ['pandas', 'numpy']

datas = []
binaries = []
hiddenimports = ['pandas', 'numpy', 'pandas.core.frame', 'pandas.core.indexes.api']

for pkg in COLLECT_PACKAGES:
    try:
        d, b, h = collect_all(pkg)
        datas += d
        binaries += b
        hiddenimports += h
    except Exception as e:
        print(f"[warn] Không collect được {pkg}: {e}")

for pkg in DATA_ONLY_PACKAGES:
    try:
        from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs
        datas += collect_data_files(pkg)
        binaries += collect_dynamic_libs(pkg)
    except Exception as e:
        print(f"[warn] Không collect data {pkg}: {e}")

# ─── Playwright browsers (chỉ headless shell + ffmpeg — scanner chỉ dùng headless)
BROWSERS_SRC = os.environ.get(
    'PLAYWRIGHT_BROWSERS_SRC',
    os.path.expanduser('~/Library/Caches/ms-playwright'),
)
BROWSER_DIRS = ['chromium_headless_shell-1234', 'ffmpeg-1011']

for name in BROWSER_DIRS:
    src = os.path.join(BROWSERS_SRC, name)
    if os.path.isdir(src):
        datas.append((src, os.path.join('browsers', name)))
        print(f"[ok] Bundle browser: {name} ({src})")
    else:
        print(f"[warn] Không tìm thấy browser: {src}")

# ─── Toàn bộ mã nguồn dự án (chạy runtime qua sys.path)
SPEC_DIR = os.environ.get('SCANNER_SPEC_DIR', SPECPATH)  # PyInstaller cung cấp SPECPATH
smart_scanner_root = os.path.abspath(os.path.join(SPEC_DIR, '..'))
for entry in os.listdir(smart_scanner_root):
    if entry.startswith(('.', '__pycache__')):
        continue
    full = os.path.join(smart_scanner_root, entry)
    if os.path.isdir(full):
        datas.append((full, entry))
    else:
        datas.append((full, '.'))

# ─── Entry point
launcher = os.path.join(SPEC_DIR, 'app_launcher.py')

block_cipher = None

a = Analysis(
    [launcher],
    pathex=[smart_scanner_root],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'PyQt5', 'PySide2', 'IPython'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

BUILD_MODE = os.environ.get('BUILD_MODE', 'onedir')  # onefile | onedir

if BUILD_MODE == 'onefile':
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.zipfiles,
        a.datas,
        [],
        name='SmartSecurityScanner',
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,   # tắt UPX để tránh hỏng binary
        console=True,
        icon=None,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
else:
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name='SmartSecurityScanner',
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=True,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
    coll = COLLECT(
        exe, a.binaries, a.zipfiles, a.datas,
        strip=False, upx=False,
        upx_exclude=[],
        name='SmartSecurityScanner',
    )
