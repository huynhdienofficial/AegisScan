# 🛡️ Smart Security Scanner

Công cụ quét lỗ hổng bảo mật (Web DAST + Infrastructure) với CLI và giao
diện Streamlit, theo kiến trúc "Security Scanning & Exploitation Platform".

> ⚠️ **Trước khi dùng, đọc [GAP_ANALYSIS.md](GAP_ANALYSIS.md)** — đây là
> nguồn thông tin CHÍNH XÁC về việc module nào đã thật sự kết nối vào CLI/UI
> và module nào mới chỉ tồn tại dưới dạng class có test. Danh sách bên dưới
> chỉ tóm tắt, không phải toàn bộ chi tiết.

## Trạng thái dự án (tóm tắt)

**Đã kết nối thật, chạy được từ CLI hoặc UI** (xem GAP_ANALYSIS.md §2 để biết chi tiết):
- Web DAST cơ bản: crawler, passive scan (headers/cookies/tech fingerprint), SQLi/XSS/RCE active scan (GET + form POST)
- Scanner bổ sung qua `cli.py --extra-scans`: SSRF, Path Traversal, SSTI, XXE, CORS, CSRF, GraphQL, JWT
- Scope Guard + Safety Profile + Rate Limiting + Circuit Breaker (chặn target ngoài phạm vi, chặn payload destructive)
- Authorization Record + RBAC cho Exploitation Module Level 2/3 (không còn tự-phê-duyệt)
- Correlation & Deduplication Engine (chuẩn hoá Unified Finding Data Model, dedup đa nguồn) + Finding Management (lifecycle/suppression)
- SQLite Storage (scan/asset/finding), Scan History & Delta (New/Fixed/Unchanged)
- SARIF/CSV export, Multi-factor Risk Engine
- Agentless port/banner check qua `cli.py --agentless-ports`

**Chỉ chạy được từ `scanner_ui.py` (Streamlit), chưa có ở CLI:** WebSocket,
File Upload, Cloud (AWS/Azure/GCP), Kubernetes, Database, OS Hardening/CIS,
SBOM, Threat Intel CVE/EPSS/KEV matching, Business Logic Testing, WAF
Evasion, Request Smuggling, Race Condition, và các module Governance/Enterprise
(SIEM/Ticketing/Compliance Mapping/Secret Vault/Agent Management).

**Đã biết là chưa hoàn chỉnh:** `governance.ScanScheduler` chỉ là hàng đợi
in-memory, chưa có daemon chạy theo `cron_expr` thật; chưa có test tích
hợp end-to-end cho `cli.py main()` với network thật (chỉ có test tích hợp
dùng crawler/handler giả — xem `tests/test_cli_integration.py`).

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
cd smart_scanner

# Tạo môi trường ảo (khuyến nghị)
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# Cài đặt dependencies
pip install -r requirements.txt

# Cài đặt Playwright browsers
playwright install

# Chạy UI
streamlit run scanner_ui.py        # hoặc: python run_ui.py
```

## Sử dụng

### CLI

```bash
# Cơ bản — sqli/xss/rce trên GET params + form POST
python cli.py --url https://target.com --scan all --output report.json

# Với Safety Profile + xác nhận quyền kiểm thử
python cli.py --url https://target.com --profile safe-active --confirm

# Quét localhost (Local Lab Mode)
python cli.py --url http://localhost:8000 --local-lab --allowlist localhost --confirm

# Dry-run (xem cấu hình trước khi quét, không gửi request nào)
python cli.py --url https://target.com --dry-run

# Scanner bổ sung + xuất SARIF/CSV + agentless port-check
python cli.py --url https://target.com --confirm \
  --extra-scans ssrf,lfi,ssti,xxe,cors,csrf,graphql \
  --agentless-ports 22,443,3306 \
  --sarif-output report.sarif --csv-output report.csv

# JWT testing cần token
python cli.py --url https://target.com --confirm \
  --extra-scans jwt --jwt-token "eyJhbGc..."
```

Danh sách cờ chính:

| Cờ | Mô tả |
|---|---|
| `--url` | Target URL (bắt buộc) |
| `--scan` | `sqli` \| `xss` \| `rce` \| `all` (mặc định `all` = cả 3) |
| `--extra-scans` | Danh sách phân cách dấu phẩy: `ssrf,lfi,ssti,xxe,cors,csrf,graphql,jwt` |
| `--jwt-token` | Token cho `--extra-scans jwt` |
| `--graphql-url` | Override endpoint GraphQL (mặc định `<url>/graphql`) |
| `--profile` | `passive` \| `safe-active` \| `authenticated` \| `deep-lab` \| `ci-fast` |
| `--allowlist` / `--denylist` | Domain/IP/CIDR, phân cách dấu phẩy |
| `--local-lab` | Cho phép quét localhost/LAN |
| `--dry-run` | Xem cấu hình dự kiến, không gửi request |
| `--confirm` | Xác nhận quyền kiểm thử target |
| `--rps` | Giới hạn Requests Per Second |
| `--db` / `--no-storage` | Đường dẫn SQLite lưu scan history (mặc định `scanner.db`) / tắt lưu |
| `--sarif-output` / `--csv-output` | Xuất thêm report SARIF/CSV |
| `--agentless-ports` | Port kiểm tra open/banner trên hostname target |

### Web UI (Streamlit)

```bash
streamlit run scanner_ui.py    # UI đầy đủ tính năng (khuyến nghị)
streamlit run app.py           # UI rút gọn (passive + sqli/xss/rce)
```

## An toàn & Kiểm soát phạm vi

- **Scope Guard**: allowlist/denylist domain-IP-CIDR, chặn localhost/private
  network trừ khi bật `--local-lab`, audit trail cho mọi quyết định cho phép/chặn.
- **Authorization Record** (`utils/authorization.py`): mọi hành động Level 2
  (active verification) trở lên yêu cầu bản ghi uỷ quyền có approver/scope/
  thời hạn hiệu lực, được RBAC xác thực — không chấp nhận tự-phê-duyệt.
- **Safety Profile + Rate Limiter + Circuit Breaker**: chặn payload
  destructive/exfiltration, giới hạn RPS, tự tạm dừng khi liên tục lỗi.
- **Exploitation Module Level 3** không bao giờ tự động chạy trên target có
  chữ "production" trong tên/URL.

Chi tiết đầy đủ về mô hình đe doạ và các lớp kiểm soát: xem tài liệu đặc tả
đi kèm dự án.

## 📦 Đóng gói thành ứng dụng chạy trực tiếp (PyInstaller)

Đóng gói dự án thành ứng dụng **không cần cài Python** trên máy người dùng.
> ⚠️ PyInstaller **không cross-compile** — phải build riêng trên từng hệ điều hành
> (build file Windows phải chạy trên Windows, file macOS phải chạy trên macOS).

### 🍎 Build trên macOS

```bash
./build_macos.sh                        # mặc định: thư mục (onedir)
BUILD_MODE=onefile ./build_macos.sh     # 1 file .exe duy nhất
```

Kết quả tại `smart_scanner/dist/SmartSecurityScanner/` (không commit vào git — xem `.gitignore`).

### 🖥️ Build trên Windows

```bat
build_windows.bat                       
set BUILD_MODE=onefile & build_windows.bat
```

Kết quả tại `smart_scanner\dist\SmartSecurityScanner\`.

### Ghi chú đóng gói
- Ứng dụng tự **bind localhost** (127.0.0.1) — an toàn, không expose ra mạng
- **Chromium headless** được đóng gói sẵn (dùng cho passive scan + XSS confirmation)
- Kích thước bản onedir ~600MB (Streamlit + Playwright + pandas), bản onefile giải nén chậm hơn khi khởi động
- Nếu cần bản gọn hơn: dùng **Streamlit Community Cloud** (deploy online) hoặc **Docker**

## Kiểm thử

```bash
# Từ thư mục gốc dự án (không phải smart_scanner/)
python -m pytest tests -q
```

Toàn bộ test không phụ thuộc network thật (dùng fake/mock handler) trừ khi
chạy `cli.py`/`app.py` trực tiếp để smoke-test thủ công.

## Tài liệu tham khảo

- [GAP_ANALYSIS.md](GAP_ANALYSIS.md) — trạng thái thật của từng module, bug đã biết, ưu tiên tiếp theo. Cập nhật mỗi lần có thay đổi lớn, coi đây là nguồn sự thật thay vì README này.
