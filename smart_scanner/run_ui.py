"""
🚀 Trình khởi động giao diện AegisScan.
Chỉ cần chạy: python run_ui.py
"""
import os
import subprocess
import sys


def main():
    # Lấy thư mục hiện tại
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    print("🛡️  Đang khởi động AegisScan...")
    print("=" * 50)

    # Khởi động Streamlit (chỉ bind localhost — bảo mật, xem data_residency.py #64)
    cmd = [sys.executable, "-m", "streamlit", "run", "scanner_ui.py",
           "--server.address", "127.0.0.1"]
    
    try:
        subprocess.run(cmd, cwd=script_dir)
    except KeyboardInterrupt:
        print("\n👋 Đã dừng.")
    except Exception as e:
        print(f"❌ Lỗi: {e}")
        print("\n💡 Nếu lỗi, hãy chạy thủ công:")
        print(f"   cd {script_dir}")
        print("   streamlit run scanner_ui.py")


if __name__ == "__main__":
    main()