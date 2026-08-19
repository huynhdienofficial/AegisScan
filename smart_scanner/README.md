# 🛡️ Smart Security Scanner

Công cụ quét lỗ hổng bảo mật tự động hỗ trợ SQLi, XSS, RCE với giao diện Streamlit.

> 📊 **Xem [GAP_ANALYSIS.md](GAP_ANALYSIS.md)** — Báo cáo rà soát khoảng trống đối chiếu toàn bộ dự án với Đặc tả kỹ thuật v2.0.

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

## Tính năng (Roadmap)

| Bước | Tính năng | Trạng thái |
|------|-----------|-----------|
| 1 | Crawler engine thu thập URL, parameters, forms | ✅ Hoàn thành |
| 2 | Active scanner: SQLi, XSS, RCE (GET parameters) | ✅ Hoàn thành |
| 3 | Passive scanner: Header & Cookie security | ✅ Hoàn thành |
| 4 | Technology fingerprinting & API discovery | ✅ Hoàn thành |
| 5 | Risk engine, Exploit manager, JSON/HTML report | ✅ Hoàn thành |
| 6 | **Form-based scanning (POST): SQLi, XSS, RCE qua form inputs** | ✅ Hoàn thành |
| 7 | **Scope Guard + Safety Profile + Rate Limiting** | ✅ Hoàn thành |
| 8 | Authentication support, session handling, CSRF bypass | 📋 Kế hoạch |
| 9 | WAF detection & false positive reduction | 📋 Kế hoạch |
| 10 | Storage SQLite, evidence store, scan compare | 📋 Kế hoạch |
| 11 | OpenAPI/GraphQL, AuthZ/IDOR, CORS testing | 📋 Kế hoạch |
| 12 | Advanced scanners: SSRF, LFI, SSTI, XXE | 📋 Kế hoạch |
| 13 | SARIF/CSV export, regression lab (Juice Shop/WebGoat/DVWA) | 📋 Kế hoạch |
| 14 | Docker deployment, SBOM, dependency scanning | 📋 Kế hoạch |
| 15 | CI/CD integration, webhook alerts | 📋 Kế hoạch |
| 16 | Enterprise: RBAC, PostgreSQL, job queue | 📋 Kế hoạch |
| 17 | **Asset Inventory** (Asset, Shadow IT, import CSV/JSON) | ✅ Hoàn thành |
| 18 | **Finding Management** (lifecycle, duplicate correlation, delta) | ✅ Hoàn thành |
| 19 | **Infra Scan Engine** (Port/Service/TLS, Network Exposure) | ✅ Hoàn thành |
| 20 | **SARIF/CSV Export + Báo cáo chuẩn 11 mục** | ✅ Hoàn thành |
| 21 | **Multi-factor Risk Engine** (CVSS + EPSS + Exposure + Asset) | ✅ Hoàn thành |
| 22 | **JWT/GraphQL/WebSocket/File Upload testing (v3.1)** | ✅ Hoàn thành |
| 23 | **Threat Intel (CVE/CPE/EPSS/KEV) + Secrets + Docker** | ✅ Hoàn thành |
| 24 | **RBAC (Viewer/Analyst/Approver/Admin)** | ✅ Hoàn thành |
| 25 | **Database Scanner** (PostgreSQL/MySQL/MSSQL/MongoDB) | ✅ Hoàn thành |
| 26 | **Kubernetes Scanner** (privileged, mounts, RBAC, SA token) | ✅ Hoàn thành |
| 27 | **WAF Evasion + Request Smuggling + Race Condition** | ✅ Hoàn thành |
| 28 | **Exploitation Module (Level 1-3) + Evidence Redaction** | ✅ Hoàn thành |
| 29 | **Remediation Workflow + Notification + Compliance Mapping** | ✅ Hoàn thành |
| 30 | **Cloud Scanner (AWS/Azure/GCP)** | ✅ Hoàn thành |
| 31 | **OS Hardening / CIS Benchmark** | ✅ Hoàn thành |
| 32 | **SIEM/Ticketing/Public API** | ✅ Hoàn thành |
| 33 | **SQLite Storage (scan history, assets, findings)** | ✅ Hoàn thành |
| 34 | **CORS/CSRF/IDOR/OpenAPI/HTTP Method tests** | ✅ Hoàn thành |
| 35 | **SSRF/LFI/SSTI/XXE Scanner + Auth Session Testing** | ✅ Hoàn thành |
| 36 | **Agent/Agentless Collector + Agent Management** | ✅ Hoàn thành |
| 37 | **SBOM Generation (CycloneDX/SPDX) + CVE Matching** | ✅ Hoàn thành |
| 38 | **Security Trend Dashboard + Top Risk + Zero-day ML** | ✅ Hoàn thành |
| 39 | **Firewall Rule Review + Exploit Module Manifest** | ✅ Hoàn thành |
| 40 | **Business Impact Scoring + Remediation Automation (Ansible)** | ✅ Hoàn thành |
| 41 | **Scan Orchestrator (on-demand/cron/event) + Business Logic Testing** | ✅ Hoàn thành |
| 42 | **Secret Vault (Encryption at Rest)** | ✅ Hoàn thành |
| 43 | **Data Residency (in-country) + Self Security Scan + Least Privilege + Localhost Binding** | ✅ Hoàn thành |
| 44 | **TOÀN BỘ 86 TÍNH NĂNG Feature List v3.1** | ✅ ✅ ✅ |

## Sử dụng

### CLI

```bash
# Cơ bản
python cli.py --url https://target.com --scan all --output report.json

# Với Safety Profile
python cli.py --url https://target.com --profile safe-active --confirm

# Quét localhost (Local Lab Mode)
python cli.py --url http://localhost:8000 --local-lab --allowlist localhost --confirm

# Dry-run (xem cấu hình trước khi quét)
python cli.py --url https://target.com --dry-run

# Giới hạn RPS
python cli.py --url https://target.com --rps 2 --confirm
```

Tùy chọn bước 7:
- `--profile`: Safety profile (`passive`, `safe-active`, `authenticated`, `deep-lab`, `ci-fast`)
- `--allowlist`: Allowlist domains (phân cách bằng dấu phẩy)
- `--denylist`: Denylist domains
- `--local-lab`: Bật Local Lab Mode — cho phép quét localhost/LAN
- `--dry-run`: Xem request dự kiến mà không gửi
- `--confirm`: Xác nhận quyền kiểm thử target
- `--rps`: Giới hạn Requests Per Second

### Web UI (Streamlit)

```bash
streamlit run app.py
```

## 📦 Đóng gói thành ứng dụng chạy trực tiếp (PyInstaller)

Đóng gói dự án thành ứng dụng **không cần cài Python** trên máy người dùng.
> ⚠️ PyInstaller **không cross-compile** — phải build riêng trên từng hệ điều hành
> (build file Windows phải chạy trên Windows, file macOS phải chạy trên macOS).

### 🍎 Build trên macOS

```bash
./build_macos.sh                        # mặc định: thư mục (onedir)
BUILD_MODE=onefile ./build_macos.sh     # 1 file .exe duy nhất
```

Kết quả tại `smart_scanner/dist/SmartSecurityScanner/`.

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

## Bước 6: Form-based Scanning (POST)

### Mô tả
Nâng cấp bộ quét để phát hiện lỗ hổng SQLi, XSS, RCE thông qua **form inputs** (HTML forms) được crawler phát hiện, bao gồm cả phương thức POST - điều mà quét GET parameters thông thường bỏ sót.

### Thay đổi chính

1. **`utils/fuzzer_engine.py`**
   - Thêm `fuzz_form()` - fuzz từng input của form qua POST (hoặc GET)
   - Giữ nguyên giá trị ban đầu của các input khác khi test
   - Thêm `run_forms()` - chạy quét hàng loạt forms với payloads

2. **`scanners/active_scanner.py`**
   - Các hàm `scan_sqli()`, `scan_xss()`, `scan_rce()` nhận thêm tham số `forms`
   - Tích hợp kết quả quét form vào danh sách vulnerability
   - `scan_all()` hỗ trợ quét forms đồng thời

3. **`fingerprint/attack_surface/exploit_manager.py`**
   - `run_scan()` nhận thêm tham số `forms`
   - Báo cáo hiển thị số forms đã quét
   - HTML report hiển thị cột `Method` (GET/POST)

4. **`cli.py` & `app.py`**
   - Truyền forms từ crawler vào quét
   - Hiển thị số forms phát hiện & quét trong UI/CLI

### Test
```bash
cd smart_scanner && python -m pytest ../tests/test_advanced_features.py -v
```

## Bước 7: Scope Guard + Safety Profile + Rate Limiting

### Mô tả
Thêm tầng **governance & an toàn** cho scanner theo Đặc tả v2.0 §2.1, §6, §18:

- **Scope Guard** — kiểm soát phạm vi quét (allowlist, denylist, Local Lab Mode, dry-run)
- **Safety Profile** — 5 profile an toàn khác nhau cho từng mục đích
- **Rate Limiting** — giới hạn RPS để tôn trọng target
- **Circuit Breaker** — tự tạm dừng khi quá tải/thất bại liên tục
- **Safety Manager** — chặn payload destructive/exfiltration/external callbacks
- **Scan Context** — tạo Scan ID + audit trail cho mỗi lần quét

### Thay đổi chính

1. **`utils/scope_guard.py`** (MỚI)
   - `ScopeGuard` — allowlist/denylist, wildcard domain, CIDR, Local Lab Mode, audit trail
   - `ScanContext` — tạo Scan ID, config hash, lưu metadata

2. **`utils/safety_profiles.py`** (MỚI)
   - `SafetyProfile` — 5 profile: passive, safe-active, authenticated, deep-lab, ci-fast
   - `RateLimiter` — giới hạn RPS
   - `CircuitBreaker` — chặn khi thất bại liên tục
   - `SafetyManager` — kiểm tra payload/url/method trước khi gửi

3. **`utils/request_handler.py`**
   - Tích hợp `SafetyManager` — kiểm tra scope/method/payload trước mỗi request
   - Rate limiter + circuit breaker tự động
   - Giới hạn kích thước response

4. **`utils/fuzzer_engine.py`**
   - Lọc payload an toàn theo safety profile trước khi fuzz
   - Ghi log payload bị chặn

5. **`crawler_core.py`**
   - Nhận `scope_guard` — chặn URL ngoài scope khi crawl
   - Trả về `scope_blocked` (số URL bị chặn)

6. **`fingerprint/attack_surface/exploit_manager.py`**
   - Nhận `scan_context` — lưu scan metadata vào report
   - Kiểm tra profile trước khi chạy scan
   - Report bao gồm safety stats

7. **`cli.py`**
   - Thêm `--profile`, `--allowlist`, `--denylist`, `--local-lab`, `--dry-run`, `--confirm`, `--rps`
   - Scope Guard kiểm tra trước khi scan
   - Tạo Scan ID + xác nhận quyền

8. **`app.py`**
   - Thêm UI cho profile, Local Lab Mode, allowlist, authorization confirm
   - Tab Safety Log hiển thị block log
   - Hiển thị Scan ID

9. **`config.yaml`**
   - Thêm cấu hình `scope:`, `safety:`, `rps`, `max_response_mb`, `circuit_breaker:`, `storage:`

### Test
```bash
cd smart_scanner && python -m pytest ../tests/test_advanced_features.py -v
```
- `test_scope_guard_blocks_out_of_scope_target`
- `test_scope_guard_blocks_localhost_without_local_lab_mode`
- `test_scope_guard_allows_localhost_with_local_lab_mode`
- `test_scope_guard_audit_trail`
- `test_safety_profile_defines_expected_config`
- `test_safety_manager_blocks_destructive_payloads`
- `test_safety_manager_blocks_out_of_scope_and_methods`
- `test_rate_limiter_controls_rps`
- `test_circuit_breaker_opens_after_consecutive_failures`
- `test_exploit_manager_blocks_injection_with_passive_profile`