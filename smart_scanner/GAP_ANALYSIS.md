# 📊 Trạng Thái Dự Án — Smart Security Scanner (cập nhật 2026-08-19)

> Bản trước (đối chiếu đặc tả v2.0) đã lỗi thời và có nhiều điểm sai lệch so
> với code thực tế (báo cáo Storage/Scope Guard/SARIF "chưa có" dù đã tồn
> tại từ lâu). File này thay thế hoàn toàn, viết lại từ việc đọc trực tiếp
> source code, không suy diễn từ README.

## 1. Nguyên tắc đọc file này

README.md liệt kê một danh sách dài "✅ Hoàn thành" — điều đó có nghĩa
**class/hàm tồn tại**, KHÔNG có nghĩa nó được **gọi thật** từ một entry point
(`cli.py`/`app.py`/`scanner_ui.py`). Một module có thể có unit test pass
100% nhưng vẫn không bao giờ chạy trong ứng dụng thật nếu không nơi nào
import nó. Bảng dưới phân biệt rõ hai trạng thái đó.

## 2. Đã kết nối thật vào entry point (không chỉ tồn tại trong test)

| Module | Entry point | Ghi chú |
|---|---|---|
| Scope Guard + Safety Profile | `cli.py`, `app.py`, `scanner_ui.py` | Allowlist/denylist/local-lab/dry-run enforce thật trước khi crawl |
| Authorization Record + Registry (`utils/authorization.py`) | `exploitation.py`, `exploitation_tool.py`, `scanner_ui.py` | Level 2/3 exploitation bắt buộc record hợp lệ + RBAC — không còn tự-phê-duyệt |
| Correlation & Deduplication Engine (`correlation_engine.py`) | `cli.py` | Chuẩn hoá Unified Finding Data Model 15 trường, dedup multi-source (active scanner + agentless) |
| SQLite Storage (`storage.py`) | `cli.py` (`--db`) | Lưu scan/asset/finding thật, có thể tắt bằng `--no-storage` |
| Scan History & Delta (`storage.compare_scans`) | `cli.py` | So sánh New/Fixed/Unchanged với scan trước cùng target |
| SARIF/CSV Export | `cli.py` (`--sarif-output`/`--csv-output`) | Đọc cả Unified Finding fields lẫn field thô kiểu cũ |
| Agentless Collector (`agents.py`) | `cli.py` (`--agentless-ports`) | Port/banner check thật trên hostname của target |
| Risk scoring | `report_exporters.MultiFactorRiskEngine.calculate_from_findings` | Nguồn tính điểm DUY NHẤT — 3 module khác (`fingerprint/attack_surface/risk_engine.py`, `.../exploit_manager.py`, `utils/risk_analyzer.py`) delegate sang đây thay vì tự tính |

## 3. Tồn tại, có test, nhưng CHƯA kết nối vào entry point (mồ côi)

| Module | Vấn đề |
|---|---|
| `finding_management.FindingManager` (suppress/reopen/correlate_duplicates) | `scanner_ui.py` chỉ gọi `create_finding`, không dùng suppression workflow hay `correlate_duplicates` — CLI mới có Correlation Engine riêng (§25), chưa hợp nhất với class này |
| `agents.AgentCollector` / `AgentManager` | Quản lý agent cài trên host (khác `AgentlessCollector`) — chưa có subcommand CLI nào cho fleet agent management, chỉ dùng trong `scanner_ui.py` demo |
| `report_exporters.ReportBuilder.build_standard_report` | Report 11 mục chuẩn — `scanner_ui.py` tự build report dict riêng thay vì gọi hàm này |
| `governance.ScanScheduler` | Lịch quét on-demand/cron/event — `cron_expr` được lưu nhưng không có daemon nào thật sự parse/chạy theo lịch |
| CLI chỉ scan SQLi/XSS/RCE + agentless port-check | 17+ scanner khác (SSRF/SSTI/JWT/GraphQL/Cloud/K8s/Database/OS-hardening...) chỉ chạy được từ `scanner_ui.py` (Streamlit), chưa có cờ CLI tương ứng |

## 4. Đã dọn trong lần rà soát này

- Xoá `smart_scanner/dist/` + `build/` (678MB output PyInstaller commit nhầm vào source tree) — tái tạo bằng `build_macos.sh`/`build_windows.bat`.
- Xoá package shim `attack_surface/` (chỉ re-export từ `fingerprint/attack_surface/`, khiến `try/except ImportError` ở 3 entry point trở thành dead code vì nhánh `except` không bao giờ chạy).
- Gộp 4 công thức risk-score không đồng nhất (mỗi cái cho điểm khác nhau trên cùng 1 tập finding) thành 1 nguồn duy nhất.
- Thay XOR "mã hóa" giả trong `SecretVault` bằng Fernet (AES + HMAC) thật.
- Vá lỗi logic khiến `level3_controlled_exploit` luôn "executed" bất kể target có phải production hay không.
- Đóng lỗ tự-phê-duyệt Level 2/3 exploitation (constructor `approved_by=` không còn tự cấp quyền).
- Thêm `.gitignore`, thư mục hiện KHÔNG phải git repo (`git init` nếu muốn có audit trail/rollback cho các thay đổi tiếp theo).

## 5. Ưu tiên tiếp theo nếu muốn tiếp tục

1. Cho CLI parity với `scanner_ui.py` (17+ scanner còn lại) — hoặc hợp nhất cả hai vào một scan-orchestration layer dùng chung, tránh mỗi entry point tự chọn import riêng.
2. Hợp nhất `finding_management.FindingManager` với `correlation_engine.CorrelationEngine` — hiện có 2 khái niệm "duplicate correlation" tồn tại song song.
3. Viết test tích hợp cho `cli.py main()` (hiện chỉ verify thủ công qua chạy thật, chưa có test tự động — cần mock network để không phụ thuộc target thật).
