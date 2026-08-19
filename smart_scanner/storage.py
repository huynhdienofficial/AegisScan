"""
SQLite Storage — lưu trữ scan history, findings, assets theo đặc tả v3.1 mục 9.

- Scan: id, target, profile, started_at, ended_at, status
- Asset: asset_id, name, type, hostname, ip, url
- Finding: finding_id, asset_id, rule_id, severity, title, status
- Evidence: finding_id, evidence_data
Không lưu plaintext password/token — luôn redact.
"""
import json
import os
import sqlite3
from datetime import datetime


class SQLiteStorage:
    """Lưu trữ dữ liệu scan trên SQLite."""

    def __init__(self, db_path='scanner.db'):
        self.db_path = db_path
        self.conn = None
        self._connect()
        self._create_tables()

    def _connect(self):
        """Kết nối SQLite."""
        os.makedirs(os.path.dirname(self.db_path) or '.', exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row

    def _create_tables(self):
        """Tạo schema database."""
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                profile TEXT,
                started_at TEXT,
                ended_at TEXT,
                status TEXT,
                config_hash TEXT,
                audit_trail TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assets (
                asset_id TEXT PRIMARY KEY,
                name TEXT,
                asset_type TEXT,
                hostname TEXT,
                ip TEXT,
                url TEXT,
                environment TEXT,
                business_criticality TEXT,
                last_scan TEXT,
                last_seen TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                asset_id TEXT,
                scan_id TEXT,
                rule_id TEXT,
                severity TEXT,
                title TEXT,
                status TEXT,
                evidence TEXT,
                created_at TEXT
            )
        ''')
        self.conn.commit()

    # ─── Scan operations ──────────────────────────────────────
    def save_scan(self, scan_data):
        """Lưu scan mới."""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO scans (scan_id, target, profile, started_at, ended_at, status, config_hash, audit_trail)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_data.get('scan_id', ''),
            scan_data.get('target', ''),
            scan_data.get('profile', ''),
            scan_data.get('started_at', ''),
            scan_data.get('ended_at', ''),
            scan_data.get('status', 'running'),
            json.dumps(scan_data.get('config_hash', {}), default=str),
            json.dumps(scan_data.get('audit_trail', []), default=str),
        ))
        self.conn.commit()

    def update_scan(self, scan_id, **kwargs):
        """Cập nhật scan."""
        cursor = self.conn.cursor()
        for key, value in kwargs.items():
            cursor.execute(f'UPDATE scans SET {key} = ? WHERE scan_id = ?', (value, scan_id))
        self.conn.commit()

    def get_scan(self, scan_id):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM scans WHERE scan_id = ?', (scan_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def list_scans(self, limit=20):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM scans ORDER BY started_at DESC LIMIT ?', (limit,))
        return [dict(r) for r in cursor.fetchall()]

    def get_previous_scan(self, target, exclude_scan_id):
        """Scan hoàn tất gần nhất trên cùng target, khác scan hiện tại — nền
        tảng cho Scan History & Delta (đặc tả §11.3: New/Fixed/Unchanged/Reopened)."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM scans WHERE target = ? AND scan_id != ? AND status = 'completed' "
            "ORDER BY started_at DESC LIMIT 1",
            (target, exclude_scan_id),
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    # ─── Asset operations ─────────────────────────────────────
    def save_asset(self, asset):
        """Lưu asset."""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO assets
            (asset_id, name, asset_type, hostname, ip, url, environment, business_criticality, last_scan, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            asset.get('asset_id', ''),
            asset.get('name', ''),
            asset.get('asset_type', 'server'),
            asset.get('hostname'),
            asset.get('ip'),
            asset.get('url'),
            asset.get('environment', 'development'),
            asset.get('business_criticality', 'medium'),
            asset.get('last_scan'),
            asset.get('last_seen'),
        ))
        self.conn.commit()

    def list_assets(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM assets')
        return [dict(r) for r in cursor.fetchall()]

    # ─── Finding operations ───────────────────────────────────
    def save_finding(self, finding):
        """Lưu finding (evidence luôn redact)."""
        from exploitation import ExploitModule
        evidence = json.dumps(finding.get('evidence', {}), default=str, ensure_ascii=False)
        evidence = ExploitModule.redact_evidence(evidence)

        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO findings
            (finding_id, asset_id, scan_id, rule_id, severity, title, status, evidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            finding.get('finding_id', ''),
            finding.get('asset_id', ''),
            finding.get('scan_id', ''),
            finding.get('rule_id', ''),
            finding.get('severity', ''),
            finding.get('title', ''),
            finding.get('status', 'suspected'),
            evidence,
            finding.get('created_at', datetime.now().isoformat()),
        ))
        self.conn.commit()

    def list_findings(self, status=None, scan_id=None, limit=50):
        cursor = self.conn.cursor()
        if scan_id:
            cursor.execute('SELECT * FROM findings WHERE scan_id = ? ORDER BY created_at DESC LIMIT ?',
                           (scan_id, limit))
        elif status:
            cursor.execute('SELECT * FROM findings WHERE status = ? ORDER BY created_at DESC LIMIT ?',
                           (status, limit))
        else:
            cursor.execute('SELECT * FROM findings ORDER BY created_at DESC LIMIT ?', (limit,))
        return [dict(r) for r in cursor.fetchall()]

    def compare_scans(self, previous_scan_id, current_scan_id):
        """Delta New/Fixed/Unchanged giữa 2 scan (đặc tả §11.3), khớp finding
        theo (rule_id, severity) — vì finding_id được sinh mới mỗi lần scan
        nên không dùng được làm khoá so sánh giữa 2 lần chạy khác nhau."""
        prev_findings = self.list_findings(scan_id=previous_scan_id, limit=10000)
        curr_findings = self.list_findings(scan_id=current_scan_id, limit=10000)

        def key(f):
            return (f['rule_id'], f['severity'])

        prev_keys = {key(f) for f in prev_findings}
        curr_keys = {key(f) for f in curr_findings}

        return {
            'previous_scan': previous_scan_id,
            'current_scan': current_scan_id,
            'new': sorted(str(k) for k in (curr_keys - prev_keys)),
            'fixed': sorted(str(k) for k in (prev_keys - curr_keys)),
            'unchanged': sorted(str(k) for k in (curr_keys & prev_keys)),
            'summary': {
                'new_count': len(curr_keys - prev_keys),
                'fixed_count': len(prev_keys - curr_keys),
                'unchanged_count': len(curr_keys & prev_keys),
            },
        }

    def get_stats(self):
        """Thống kê database."""
        cursor = self.conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM scans')
        scan_count = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM assets')
        asset_count = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM findings')
        finding_count = cursor.fetchone()[0]
        cursor.execute('SELECT severity, COUNT(*) FROM findings GROUP BY severity')
        by_severity = {r[0]: r[1] for r in cursor.fetchall()}
        return {
            'scans': scan_count,
            'assets': asset_count,
            'findings': finding_count,
            'by_severity': by_severity,
            'db_path': self.db_path,
        }

    def close(self):
        if self.conn:
            self.conn.close()