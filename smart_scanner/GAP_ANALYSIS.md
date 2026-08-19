# 📊 Trạng Thái Dự Án — AegisScan (cập nhật 2026-08-19)

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
| `finding_management.FindingManager` ↔ `correlation_engine.CorrelationEngine` | `scanner_ui.py` (khối 4B1), `tests/test_correlation_engine.py` | `create_finding_from_unified`/`import_from_correlation_engine` — CorrelationEngine dedup trước, FindingManager quản lý vòng đời/suppression sau. `correlate_duplicates()` cũng đổi khoá theo đúng spec §25.1 (Asset+Endpoint+CWE+Parameter, bỏ evidence_hash quá chặt) |
| SSRF/PathTraversal/SSTI/XXE/CORS/CSRF/GraphQL/JWT | `cli.py` (`--extra-scans`) | Trước đây chỉ chạy trong `scanner_ui.py`; nay CLI cũng chạy được, kết quả đưa vào Correlation Engine như nguồn thứ 3 |
| `cli.py main()` | `tests/test_cli_integration.py` | Test tích hợp mock `AsyncCrawlerEngine.start`/`RequestHandler.send_request` (không chạm mạng thật) — verify full flow, dry-run không gọi network, target ngoài allowlist bị chặn, storage/delta/SARIF/CSV đều được ghi |

## 3. Tồn tại, có test, nhưng CHƯA kết nối vào entry point (mồ côi)

| Module | Vấn đề |
|---|---|
| `agents.AgentCollector` / `AgentManager` | Quản lý agent cài trên host (khác `AgentlessCollector`) — chưa có subcommand CLI nào cho fleet agent management, chỉ dùng trong `scanner_ui.py` demo |
| `report_exporters.ReportBuilder.build_standard_report` | Report 11 mục chuẩn — `scanner_ui.py` tự build report dict riêng thay vì gọi hàm này |
| `governance.ScanScheduler` | Lịch quét on-demand/cron/event — `cron_expr` được lưu nhưng không có daemon nào thật sự parse/chạy theo lịch |
| CLI vẫn thiếu WebSocket/FileUpload/Cloud/K8s/Database/OS-hardening | Cần input đặc thù (ws URL, upload endpoint, cloud config JSON, K8s manifest, DB connection) khó tổng quát hoá qua 1 cờ CLI đơn giản như 8 scanner web vừa thêm |

## 4. Bug nghiêm trọng đã phát hiện và vá trong lần rà soát này

**Lỗi async/await khiến 11 scanner/hàm luôn báo "an toàn" giả** trên toàn bộ
codebase: `request_handler.send_request()` là `async def` (aiohttp) nhưng
nhiều nơi gọi nó KHÔNG `await` — `resp` chỉ là coroutine chưa chạy, mọi
`getattr(resp, 'status_code'/'text', default)` luôn trả về giá trị mặc định
nên các check luôn kết luận "không có lỗ hổng" bất kể target thật có vấn đề
gì hay không. Xác nhận bằng AST scan toàn bộ `smart_scanner/**/*.py`
(0 chỗ sót sau khi vá), gồm:

- `scanners/web/input_validation.py`: SSRFScanner, PathTraversalScanner, SSTIScanner, XXEScanner
- `scanners/web/jwt_scanner.py`, `graphql_scanner.py`, `websocket_scanner.py`, `file_upload_scanner.py`
- `scanners/web/advanced_scanners.py`: WAFEvasionScanner, RequestSmugglingScanner
- `governance.py`: BusinessLogicScanner.scan_price_logic/scan_coupon_abuse
- `scanner_ui.py`: khối IDOR/Authorization Testing (gọi `handler.send_request()` trực tiếp, không qua class riêng)

Test cũ chỉ test nhánh `request_handler=None` nên chưa từng phát hiện.
`tests/test_async_scan_bugfix.py` xác nhận bằng fake async handler cho từng
scanner (verify test fail đúng cách trên code cũ qua `git stash` trước khi
khôi phục bản vá cho lô đầu tiên).

## 5. Đã dọn ở các lần rà soát trước

- Xoá `smart_scanner/dist/` + `build/` (678MB output PyInstaller commit nhầm vào source tree) — tái tạo bằng `build_macos.sh`/`build_windows.bat`.
- Xoá package shim `attack_surface/` (chỉ re-export từ `fingerprint/attack_surface/`, khiến `try/except ImportError` ở 3 entry point trở thành dead code vì nhánh `except` không bao giờ chạy).
- Gộp 4 công thức risk-score không đồng nhất (mỗi cái cho điểm khác nhau trên cùng 1 tập finding) thành 1 nguồn duy nhất.
- Thay XOR "mã hóa" giả trong `SecretVault` bằng Fernet (AES + HMAC) thật.
- Vá lỗi logic khiến `level3_controlled_exploit` luôn "executed" bất kể target có phải production hay không.
- Đóng lỗ tự-phê-duyệt Level 2/3 exploitation (constructor `approved_by=` không còn tự cấp quyền).
- Thêm `.gitignore`; dự án hiện ĐÃ có git repo (`git init` + commit từ 2026-08-19).

## 6. Ưu tiên tiếp theo nếu muốn tiếp tục

1. WebSocket/FileUpload/Cloud/K8s/Database/OS-hardening scanner vẫn chưa có cờ CLI — cần thiết kế input format phù hợp (file config JSON?) thay vì URL đơn giản.
2. `governance.ScanScheduler` vẫn chỉ là hàng đợi in-memory, không có daemon thật chạy theo `cron_expr`.
3. `agents.AgentCollector`/`AgentManager` và `report_exporters.ReportBuilder.build_standard_report` vẫn mồ côi (mục 3) — chưa có subcommand/entry point phù hợp.
