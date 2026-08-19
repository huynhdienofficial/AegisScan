"""
Test tích hợp cho cli.py main() — chạy toàn bộ luồng CLI thật (argparse →
Scope Guard → Safety Manager → crawl → scan → Correlation Engine → SARIF/CSV
→ Storage → Delta) nhưng KHÔNG chạm mạng thật: mock
`AsyncCrawlerEngine.start` (Playwright) và `RequestHandler.send_request`
(aiohttp) ở đúng lớp/method mà cli.py gọi tới.

Trước đây cli.py chỉ được verify thủ công bằng cách chạy thật nhắm vào
books.toscrape.com (xem lịch sử làm việc) — không có test tự động nào khoá
lại hành vi của toàn bộ main(). File này lấp khoảng trống đó.
"""
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
SMART = ROOT / 'smart_scanner'
sys.path.insert(0, str(SMART))

from crawler_core import AsyncCrawlerEngine
from utils.request_handler import RequestHandler
import cli


FAKE_CRAWL_EMPTY = {
    'urls': ['https://fake-target.test/'],
    'parameters': [],
    'forms': [],
    'scope_blocked': 0,
}

FAKE_CRAWL_WITH_PARAM = {
    'urls': ['https://fake-target.test/search'],
    'parameters': [{'url': 'https://fake-target.test/search', 'name': 'q', 'method': 'GET'}],
    'forms': [],
    'scope_blocked': 0,
}


def _run_cli(argv, monkeypatch, crawl_result=None, send_response=None):
    """Chạy cli.main() với sys.argv đã patch, crawler/network đã mock."""
    monkeypatch.setattr(sys, 'argv', ['cli.py'] + argv)
    crawl_result = crawl_result or FAKE_CRAWL_EMPTY
    response = send_response or SimpleNamespace(status_code=200, text='ok', headers={})

    with patch.object(AsyncCrawlerEngine, 'start', new=AsyncMock(return_value=dict(crawl_result))), \
         patch.object(RequestHandler, 'send_request', new=AsyncMock(return_value=response)):
        cli.main()


def test_cli_main_runs_full_flow_without_real_network(tmp_path, monkeypatch, capsys):
    """Luồng cơ bản: crawl (mock) -> sqli/xss/rce scan (0 param -> 0 request
    thật) -> report -> correlation -> storage -> delta. Không có --extra-scans
    nên RequestHandler.send_request không cần được gọi tới ở path này."""
    output = tmp_path / 'report.json'
    db = tmp_path / 'scan.db'

    _run_cli([
        '--url', 'https://fake-target.test/',
        '--confirm', '--scan', 'sqli',
        '--output', str(output), '--db', str(db),
    ], monkeypatch)

    captured = capsys.readouterr()
    assert 'Scan ID' in captured.out
    assert output.exists()
    assert (tmp_path / 'report.correlated.json').exists()
    assert db.exists()
    assert 'Storage:' in captured.out
    assert 'Chưa có scan trước đó' in captured.out


def test_cli_main_persists_scan_to_storage_and_computes_delta_on_rerun(tmp_path, monkeypatch, capsys):
    """Chạy 2 lần liên tiếp trên cùng target/db — lần 2 phải thấy scan
    trước đó và tính được delta (khoá lại tính năng Scan History & Delta)."""
    db = tmp_path / 'scan.db'

    _run_cli([
        '--url', 'https://fake-target.test/',
        '--confirm', '--scan', 'sqli',
        '--output', str(tmp_path / 'r1.json'), '--db', str(db),
    ], monkeypatch)

    _run_cli([
        '--url', 'https://fake-target.test/',
        '--confirm', '--scan', 'sqli',
        '--output', str(tmp_path / 'r2.json'), '--db', str(db),
    ], monkeypatch)

    captured = capsys.readouterr()
    assert 'Delta so với scan trước' in captured.out
    assert '+0 New, -0 Fixed, =0 Unchanged' in captured.out


def test_cli_main_extra_scans_use_mocked_handler_not_real_network(tmp_path, monkeypatch, capsys):
    """--extra-scans ssrf phải chạy qua RequestHandler.send_request đã mock
    (nếu code còn lỗi thiếu await, AsyncMock trả về coroutine sai cách sẽ
    raise ngay — test này cũng gián tiếp canh giữ regression async/await)."""
    output = tmp_path / 'report.json'

    _run_cli([
        '--url', 'https://fake-target.test/',
        '--confirm', '--scan', 'sqli', '--extra-scans', 'ssrf,cors',
        '--output', str(output), '--db', str(tmp_path / 'scan.db'),
        '--no-storage',
    ], monkeypatch, crawl_result=FAKE_CRAWL_WITH_PARAM)

    captured = capsys.readouterr()
    assert 'Extra scans (ssrf, cors)' in captured.out
    assert output.exists()


def test_cli_main_sarif_and_csv_output_written(tmp_path, monkeypatch):
    sarif_path = tmp_path / 'report.sarif'
    csv_path = tmp_path / 'report.csv'

    _run_cli([
        '--url', 'https://fake-target.test/',
        '--confirm', '--scan', 'sqli',
        '--output', str(tmp_path / 'report.json'),
        '--sarif-output', str(sarif_path), '--csv-output', str(csv_path),
        '--no-storage',
    ], monkeypatch)

    assert sarif_path.exists()
    assert csv_path.exists()
    sarif = json.loads(sarif_path.read_text(encoding='utf-8'))
    assert sarif['version'] == '2.1.0'


def test_cli_main_dry_run_makes_no_network_calls_at_all(tmp_path, monkeypatch, capsys):
    """--dry-run phải return sớm trước khi crawl/scan — patch crawler/handler
    với side_effect raise để đảm bảo chúng KHÔNG bao giờ được gọi."""
    monkeypatch.setattr(sys, 'argv', [
        'cli.py', '--url', 'https://fake-target.test/', '--dry-run', '--confirm',
    ])

    def _boom(*a, **kw):
        raise AssertionError("dry-run không được phép gọi crawler/network")

    with patch.object(AsyncCrawlerEngine, 'start', new=AsyncMock(side_effect=_boom)), \
         patch.object(RequestHandler, 'send_request', new=AsyncMock(side_effect=_boom)):
        cli.main()

    captured = capsys.readouterr()
    assert 'Dry-run' in captured.out
    assert 'không gửi request nào' in captured.out


def test_cli_main_rejects_out_of_scope_target(monkeypatch, capsys):
    """Target không nằm trong allowlist phải bị chặn và exit(1) trước khi
    chạm tới crawler/network."""
    monkeypatch.setattr(sys, 'argv', [
        'cli.py', '--url', 'https://evil.example.com/', '--confirm',
        '--allowlist', 'only-this-host.test',
    ])

    def _boom(*a, **kw):
        raise AssertionError("target ngoài allowlist không được phép chạm network")

    with patch.object(AsyncCrawlerEngine, 'start', new=AsyncMock(side_effect=_boom)):
        try:
            cli.main()
            assert False, "phải sys.exit(1) khi target ngoài allowlist"
        except SystemExit as e:
            assert e.code == 1

    captured = capsys.readouterr()
    assert 'không nằm trong allowlist' in captured.out or 'bị chặn' in captured.out
