"""
🚀 App Launcher — Entry point cho bản đóng gói PyInstaller.
Chạy Streamlit app IN-PROCESS (không cần Python cài sẵn trên máy người dùng).

Cách dùng khi build:
    pyinstaller packaging/smart_scanner.spec
"""
import os
import sys

# ─── Xác định thư mục chứa scanner_ui.py ────────────────────
# Các vị trí có thể chứa scanner_ui.py:
#   - Bản đóng gói onefile:  sys._MEIPASS (giải nén tạm)
#   - Bản đóng gói onedir:   _internal/ (chứa toàn bộ project)
#   - Chạy dev:              thư mục launcher (packaging/) hoặc cha của nó
def _candidate_dirs():
    dirs = []
    if getattr(sys, 'frozen', False):
        meipass = getattr(sys, '_MEIPASS', None)
        if meipass:
            dirs.append(meipass)
        dirs.append(os.path.dirname(os.path.abspath(__file__)))
    else:
        here = os.path.dirname(os.path.abspath(__file__))
        dirs.append(here)                    # packaging/
        dirs.append(os.path.dirname(here))   # smart_scanner/
    return dirs

APP_DIR = next(
    (d for d in _candidate_dirs() if os.path.exists(os.path.join(d, 'scanner_ui.py'))),
    _candidate_dirs()[0],
)
SCRIPT_PATH = os.path.join(APP_DIR, 'scanner_ui.py')
sys.path.insert(0, APP_DIR)
os.chdir(APP_DIR)

# ─── Cấu hình môi trường ────────────────────────────────────
os.environ.setdefault('STREAMLIT_SERVER_ADDRESS', '127.0.0.1')
os.environ.setdefault('STREAMLIT_SERVER_HEADLESS', 'true')
os.environ.setdefault('STREAMLIT_BROWSER_GATHER_USAGE_STATS', 'false')

# Playwright browsers đóng gói sẵn trong thư mục browsers/
BROWSERS_DIR = os.path.join(APP_DIR, 'browsers')
if not os.path.isdir(BROWSERS_DIR):
    for d in _candidate_dirs():
        if os.path.isdir(os.path.join(d, 'browsers')):
            BROWSERS_DIR = os.path.join(d, 'browsers')
            break
if os.path.isdir(BROWSERS_DIR):
    os.environ['PLAYWRIGHT_BROWSERS_PATH'] = BROWSERS_DIR


def main():
    if not os.path.exists(SCRIPT_PATH):
        print(f"❌ Không tìm thấy {SCRIPT_PATH}")
        print("   Bản đóng gói bị lỗi — hãy build lại từ mã nguồn.")
        input("Nhấn Enter để thoát...")
        return 1

    # ─── Cấu hình Streamlit (bắt buộc dùng set_option khi chạy in-process) ───
    from streamlit import config as st_config
    from streamlit.web import bootstrap as bootstrap

    # Chỉ bind localhost — KHÔNG expose ra mạng (data_residency.py #64)
    st_config.set_option('server.address', '127.0.0.1')
    st_config.set_option('server.headless', True)
    st_config.set_option('server.port', 8501)
    st_config.set_option('browser.gatherUsageStats', False)
    st_config.set_option('server.allowCrossOriginRequests', False)

    # ─── Diagnostics (chỉ trong bản debug) ───────────────────
    try:
        with open(os.path.join(os.environ.get('TMPDIR', '/tmp'), 'frozen_debug.log'), 'w') as _f:
            import streamlit
            import streamlit.file_util as _fu
            _f.write(f'frozen: {getattr(sys, "frozen", False)}\n')
            _f.write(f'MEIPASS: {getattr(sys, "_MEIPASS", "none")}\n')
            _f.write(f'APP_DIR: {APP_DIR}\n')
            _f.write(f'streamlit.__file__: {streamlit.__file__}\n')
            _f.write(f'fu.__file__: {_fu.__file__}\n')
            _f.write(f'get_static_dir(): {_fu.get_static_dir()}\n')
            _f.write(f'isdir(static): {os.path.isdir(_fu.get_static_dir())}\n')
    except Exception as _e:
        print(f'[debug] {_e}')

    bootstrap.run(SCRIPT_PATH, False, [SCRIPT_PATH], {})
    return 0


if __name__ == '__main__':
    sys.exit(main())
