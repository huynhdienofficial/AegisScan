# 🛡️ AegisScan

Nền tảng quét & khai thác lỗ hổng bảo mật ("Security Scanning & Exploitation
Platform") gồm engine crawl bất đồng bộ, các scanner passive/active cho Web
DAST, module hạ tầng (agentless port check), engine chấm điểm rủi ro, và hai
giao diện sử dụng: CLI (`cli.py`) và Web UI Streamlit (`scanner_ui.py`).

> ⚠️ **Đọc [smart_scanner/GAP_ANALYSIS.md](smart_scanner/GAP_ANALYSIS.md) trước khi dùng.**
> Đây là nguồn thông tin chính xác nhất về việc module nào đã thật sự nối vào
> CLI/UI và module nào mới chỉ tồn tại dưới dạng class có test đơn lẻ. Phần
> tóm tắt bên dưới không thay thế được tài liệu đó.

## Dự án này dùng để làm gì

Đây là một **security scanner nội bộ** cho phép:
- Tự động crawl một target web (Playwright, bất đồng bộ) để tìm URL, tham số, form.
- Chạy **passive scan**: security headers, cookie flags, technology fingerprinting.
- Chạy **active scan**: SQL Injection, XSS, RCE trên GET params và form POST — và
  các scanner mở rộng (SSRF, Path Traversal, SSTI, XXE, CORS, CSRF, GraphQL, JWT)
  qua cờ `--extra-scans`.
- Kiểm tra hạ tầng cơ bản (agentless): quét port/banner trên hostname target.
- Tổng hợp kết quả qua **Correlation & Deduplication Engine** thành Unified
  Finding Data Model, chấm điểm rủi ro tổng thể (Multi-factor Risk Engine),
  và xuất báo cáo (JSON, HTML, SARIF, CSV).
- Ghi lịch sử scan vào SQLite, so sánh delta giữa các lần scan (New/Fixed/Unchanged).
- Kiểm soát phạm vi & an toàn: Scope Guard (allowlist/denylist/local-lab mode),
  Safety Profile, Rate Limiter, Circuit Breaker, Authorization Record + RBAC
  cho các hành động khai thác mức cao hơn.

**Trạng thái thật của dự án** (tóm tắt, chi tiết xem GAP_ANALYSIS.md):

| Nhóm | Trạng thái |
|---|---|
| Web DAST (crawler, passive, SQLi/XSS/RCE active), Scope Guard, Safety Profile, Correlation/Dedup, SQLite storage, SARIF/CSV export, agentless port-check | ✅ Đã nối vào CLI **và** UI, chạy được thật |
| Scanner mở rộng: SSRF, LFI, SSTI, XXE, CORS, CSRF, GraphQL, JWT | ✅ Chạy được qua `cli.py --extra-scans` |
| WebSocket, File Upload, Cloud (AWS/Azure/GCP), Kubernetes, Database, OS Hardening/CIS, SBOM, Threat Intel (CVE/EPSS/KEV), Business Logic Testing, WAF Evasion, Request Smuggling, Race Condition, Governance/Enterprise (SIEM/Ticketing/Compliance/Secret Vault/Agent Management) | ⚠️ Chỉ chạy được từ `scanner_ui.py` (Streamlit), **chưa có ở CLI** |
| `governance.ScanScheduler` | ⚠️ Mới là hàng đợi in-memory, chưa có daemon chạy theo `cron_expr` thật |
| Test end-to-end `cli.py main()` với network thật | ❌ Chưa có — test hiện tại dùng crawler/handler giả (`tests/test_cli_integration.py`) |

## Cấu trúc thư mục

```
SecutiryScan/
├── setup_macos.sh, run_ui_macos.sh   # script tiện ích macOS (chạy từ gốc dự án)
├── build_macos.sh, build_windows.bat # đóng gói PyInstaller
├── tests/                            # toàn bộ test (pytest, không phụ thuộc network thật)
└── smart_scanner/                    # mã nguồn chính
    ├── cli.py                        # entry point CLI
    ├── app.py                        # UI Streamlit rút gọn
    ├── scanner_ui.py                 # UI Streamlit đầy đủ tính năng (khuyến nghị)
    ├── crawler_core.py               # crawler bất đồng bộ (Playwright)
    ├── correlation_engine.py         # dedup + chuẩn hoá finding
    ├── finding_management.py         # lifecycle/suppression finding
    ├── storage.py                    # SQLite: scan history, asset, finding, delta
    ├── report_exporters.py           # SARIF/CSV export
    ├── exploitation.py, exploitation_tool.py  # module khai thác (Level 2/3)
    ├── threat_intel.py, sbom.py, data_residency.py, governance.py, enterprise.py, agents.py
    │                                # module Web-UI-only, xem GAP_ANALYSIS.md
    ├── discovery/                   # API discovery
    ├── fingerprint/                 # technology detector, attack surface, risk engine
    ├── scanners/                    # passive scanner, active scanner, scanner web mở rộng
    ├── payloads/                    # payload SQLi/XSS/RCE...
    └── utils/                       # scope guard, safety profile, request handler, risk analyzer...
```

## Cài đặt

### 🍎 macOS (tự động)

```bash
# Từ thư mục gốc dự án
./setup_macos.sh        # Tạo venv + cài dependencies + Playwright Chromium
./run_ui_macos.sh       # Khởi động UI (http://localhost:8501)
```

### 🖥️ Windows

```bat
cd smart_scanner
pip install -r requirements.txt
playwright install
run_ui.bat
```

### 🐍 Thủ công (bất kỳ OS nào)

```bash
git clone <your-repo-url>
cd SecutiryScan

# Tạo môi trường ảo (khuyến nghị)
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# Cài đặt dependencies
pip install -r smart_scanner/requirements.txt

# Cài đặt Playwright browsers
playwright install chromium

# Chạy UI
cd smart_scanner
streamlit run scanner_ui.py        # hoặc: python run_ui.py
```

## Sử dụng

### CLI

```bash
# Cơ bản — sqli/xss/rce trên GET params + form POST
python smart_scanner/cli.py --url https://target.com --scan all --output report.json

# Với Safety Profile + xác nhận quyền kiểm thử
python smart_scanner/cli.py --url https://target.com --profile safe-active --confirm

# Quét localhost (Local Lab Mode — mặc định đã BẬT)
python smart_scanner/cli.py --url http://localhost:8000 --allowlist localhost --confirm

# Dry-run (xem cấu hình trước khi quét, không gửi request nào)
python smart_scanner/cli.py --url https://target.com --dry-run

# Scanner bổ sung + xuất SARIF/CSV + agentless port-check
python smart_scanner/cli.py --url https://target.com --confirm \
  --extra-scans ssrf,lfi,ssti,xxe,cors,csrf,graphql \
  --agentless-ports 22,443,3306 \
  --sarif-output report.sarif --csv-output report.csv

# JWT testing cần token
python smart_scanner/cli.py --url https://target.com --confirm \
  --extra-scans jwt --jwt-token "eyJhbGc..."
```

Danh sách cờ chính:

| Cờ | Mô tả |
|---|---|
| `--url` | Target URL (bắt buộc) |
| `--scan` | `sqli` \| `xss` \| `rce` \| `all` (mặc định `all` = cả 3) |
| `--crawl-depth`, `--concurrency` | Độ sâu crawl, số luồng đồng thời |
| `--extra-scans` | Danh sách phân cách dấu phẩy: `ssrf,lfi,ssti,xxe,cors,csrf,graphql,jwt` |
| `--jwt-token` | Token cho `--extra-scans jwt` |
| `--graphql-url` | Override endpoint GraphQL (mặc định `<url>/graphql`) |
| `--profile` | `passive` \| `safe-active` \| `authenticated` \| `deep-lab` \| `ci-fast` |
| `--allowlist` / `--denylist` | Domain/IP/CIDR, phân cách dấu phẩy |
| `--local-lab` / `--no-local-lab` | Bật/tắt quét localhost/LAN (mặc định: BẬT) |
| `--dry-run` | Xem cấu hình dự kiến, không gửi request |
| `--confirm` | Xác nhận quyền kiểm thử target |
| `--rps` | Giới hạn Requests Per Second |
| `--no-verify-ssl` | Bỏ qua xác minh SSL (target chứng chỉ lỗi) |
| `--db` / `--no-storage` | Đường dẫn SQLite lưu scan history (mặc định `scanner.db`) / tắt lưu |
| `--sarif-output` / `--csv-output` | Xuất thêm report SARIF/CSV |
| `--agentless-ports` | Port kiểm tra open/banner trên hostname target |

Xem đầy đủ: `python smart_scanner/cli.py --help`.

### Web UI (Streamlit)

```bash
cd smart_scanner
streamlit run scanner_ui.py    # UI đầy đủ tính năng (khuyến nghị)
streamlit run app.py           # UI rút gọn (passive + sqli/xss/rce)
```

Trong UI: nhập Target URL ở sidebar, chọn Safety Profile, bật/tắt Local Lab
Mode, khai báo allowlist nếu cần, tick "Tôi có quyền kiểm thử target này" rồi
bấm **Start Scan**. Sau khi scan xong, tab "Reports" (hoặc khu vực cuối
trang) cho phép tải báo cáo dạng **JSON** và **HTML**.

## An toàn & Kiểm soát phạm vi

- **Scope Guard**: allowlist/denylist domain-IP-CIDR, chặn localhost/private
  network trừ khi bật Local Lab Mode (mặc định đã bật), audit trail cho mọi
  quyết định cho phép/chặn.
- **Authorization Record** (`utils/authorization.py`): hành động khai thác
  Level 2 (active verification) trở lên yêu cầu bản ghi uỷ quyền có
  approver/scope/thời hạn hiệu lực, được RBAC xác thực — không chấp nhận
  tự-phê-duyệt.
- **Safety Profile + Rate Limiter + Circuit Breaker**: chặn payload
  destructive/exfiltration, giới hạn RPS, tự tạm dừng khi liên tục lỗi.
- **Exploitation Module Level 3** không bao giờ tự động chạy trên target có
  chữ "production" trong tên/URL.

## Đóng gói thành ứng dụng chạy trực tiếp (PyInstaller)

Đóng gói thành ứng dụng **không cần cài Python** trên máy người dùng.
> ⚠️ PyInstaller **không cross-compile** — phải build riêng trên từng hệ điều hành.

```bash
# macOS
./build_macos.sh                        # mặc định: thư mục (onedir)
BUILD_MODE=onefile ./build_macos.sh     # 1 file duy nhất
```

```bat
:: Windows
build_windows.bat
set BUILD_MODE=onefile & build_windows.bat
```

Kết quả tại `smart_scanner/dist/AegisScan/` (không commit vào git).

- Ứng dụng tự **bind localhost** (127.0.0.1) — không expose ra mạng.
- **Chromium headless** được đóng gói sẵn (passive scan + XSS confirmation).
- Bản onedir ~600MB (Streamlit + Playwright + pandas); bản onefile giải nén chậm hơn khi khởi động.
- Cần bản gọn hơn: dùng Streamlit Community Cloud hoặc Docker.

## Kiểm thử

```bash
# Từ thư mục gốc dự án
python -m pytest tests -q
```

Toàn bộ test không phụ thuộc network thật (dùng fake/mock handler), trừ khi
chạy `cli.py`/`app.py` trực tiếp để smoke-test thủ công.

## Tài liệu tham khảo

- [smart_scanner/GAP_ANALYSIS.md](smart_scanner/GAP_ANALYSIS.md) — trạng thái thật
  của từng module, bug đã biết, ưu tiên tiếp theo. Coi đây là nguồn sự thật
  thay vì README này khi có mâu thuẫn.
- [smart_scanner/README.md](smart_scanner/README.md) — bản README gốc bên trong
  thư mục mã nguồn (nội dung tương đương, cùng nguồn thông tin).
