"""
Scan History & Delta (đặc tả §11.3): storage.get_previous_scan() +
storage.compare_scans() — trước đây SQLiteStorage được viết đầy đủ nhưng
không nơi nào (cli.py/app.py) gọi tới, nên scan history/delta chỉ tồn tại
trên giấy. Test này khoá lại hành vi sau khi wire vào cli.py.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMART = ROOT / 'smart_scanner'
sys.path.insert(0, str(SMART))

from storage import SQLiteStorage


def _save_scan_with_findings(storage, scan_id, target, findings):
    storage.save_scan({'scan_id': scan_id, 'target': target, 'status': 'completed',
                        'started_at': f'2026-01-0{scan_id[-1]}T00:00:00'})
    for i, f in enumerate(findings):
        storage.save_finding({
            'finding_id': f'{scan_id}-{i}', 'scan_id': scan_id,
            'rule_id': f['rule_id'], 'severity': f['severity'], 'title': f['rule_id'],
        })


def test_get_previous_scan_returns_none_on_first_scan(tmp_path):
    storage = SQLiteStorage(db_path=str(tmp_path / 'd.db'))
    storage.save_scan({'scan_id': 'S1', 'target': 'https://a.com', 'status': 'completed',
                        'started_at': '2026-01-01T00:00:00'})
    assert storage.get_previous_scan('https://a.com', exclude_scan_id='S1') is None


def test_get_previous_scan_finds_most_recent_completed_scan_same_target(tmp_path):
    storage = SQLiteStorage(db_path=str(tmp_path / 'd.db'))
    storage.save_scan({'scan_id': 'S1', 'target': 'https://a.com', 'status': 'completed',
                        'started_at': '2026-01-01T00:00:00'})
    storage.save_scan({'scan_id': 'S2', 'target': 'https://b.com', 'status': 'completed',
                        'started_at': '2026-01-02T00:00:00'})
    storage.save_scan({'scan_id': 'S3', 'target': 'https://a.com', 'status': 'completed',
                        'started_at': '2026-01-03T00:00:00'})

    prev = storage.get_previous_scan('https://a.com', exclude_scan_id='S3')
    assert prev['scan_id'] == 'S1'  # không lẫn với S2 (target khác)


def test_compare_scans_computes_new_fixed_unchanged(tmp_path):
    storage = SQLiteStorage(db_path=str(tmp_path / 'd.db'))

    _save_scan_with_findings(storage, 'SCAN-001', 'https://a.com', [
        {'rule_id': 'CWE-89', 'severity': 'Critical'},   # sẽ Fixed (biến mất ở lần 2)
        {'rule_id': 'CWE-79', 'severity': 'High'},        # Unchanged
    ])
    _save_scan_with_findings(storage, 'SCAN-002', 'https://a.com', [
        {'rule_id': 'CWE-79', 'severity': 'High'},        # Unchanged
        {'rule_id': 'CWE-352', 'severity': 'Medium'},      # New
    ])

    delta = storage.compare_scans('SCAN-001', 'SCAN-002')
    assert delta['summary']['new_count'] == 1
    assert delta['summary']['fixed_count'] == 1
    assert delta['summary']['unchanged_count'] == 1
