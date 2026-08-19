"""
Finding Management — theo đặc tả v3.1 mục 11.

- Evidence Engine: mỗi finding có detection method, evidence, source, timestamp, scanner
- Finding Status Lifecycle: Suspected → Verified → Confirmed → Resolved/Accepted Risk
- Duplicate Correlation: gom nhóm finding trùng theo endpoint + rule + evidence hash
- Suppression / Exception Workflow: lý do, approver, hết hạn, auto-reopen
- Scan History & Delta: New/Fixed/Unchanged/Reopened
"""
import hashlib
import json
from datetime import datetime, timedelta


class Finding:
    """Một finding với evidence và vòng đời trạng thái."""

    STATUS_FLOW = ['suspected', 'verified', 'confirmed', 'resolved', 'accepted_risk']

    def __init__(self, finding_id, asset_id, rule_id, severity, title,
                 description='', evidence=None, cwe=None, owasp=None, cvss=None,
                 source='scanner', detection_method='', status='suspected',
                 endpoint=None, parameter=None, payload=None, confidence='Low',
                 suppressed=False, suppression_reason=None, suppression_approver=None,
                 suppression_expires=None, created_at=None):
        self.finding_id = finding_id
        self.asset_id = asset_id
        self.rule_id = rule_id
        self.severity = severity
        self.title = title
        self.description = description
        self.evidence = evidence or {}
        self.cwe = cwe
        self.owasp = owasp
        self.cvss = cvss
        self.source = source
        self.detection_method = detection_method
        self.status = status if status in self.STATUS_FLOW else 'suspected'
        self.endpoint = endpoint
        self.parameter = parameter
        self.payload = payload
        self.confidence = confidence
        self.suppressed = suppressed
        self.suppression_reason = suppression_reason
        self.suppression_approver = suppression_approver
        self.suppression_expires = suppression_expires
        self.created_at = created_at or datetime.now().isoformat()
        self.updated_at = self.created_at
        self.status_history = [{'status': self.status, 'at': self.created_at}]

    def update_status(self, new_status):
        """Cập nhật trạng thái finding."""
        if new_status in self.STATUS_FLOW:
            self.status = new_status
            self.updated_at = datetime.now().isoformat()
            self.status_history.append({'status': new_status, 'at': self.updated_at})

    def suppress(self, reason, approver, expires_in_days=30):
        """Suppress finding với lý do + approver + ngày hết hạn."""
        self.suppressed = True
        self.suppression_reason = reason
        self.suppression_approver = approver
        self.suppression_expires = (datetime.now() + timedelta(days=expires_in_days)).isoformat()

    def is_suppression_expired(self):
        """Kiểm tra suppression đã hết hạn chưa."""
        if not self.suppression_expires:
            return False
        expires = datetime.fromisoformat(self.suppression_expires)
        return datetime.now() > expires

    def check_auto_reopen(self):
        """Nếu suppression hết hạn → tự động reopen về 'verified'."""
        if self.suppressed and self.is_suppression_expired():
            self.suppressed = False
            self.update_status('verified')
            return True
        return False

    def evidence_hash(self):
        """Hash evidence để duplicate correlation."""
        evidence_str = json.dumps(self.evidence, sort_keys=True, default=str)
        return hashlib.sha256(evidence_str.encode()).hexdigest()[:16]

    def to_dict(self):
        return {
            'finding_id': self.finding_id,
            'asset_id': self.asset_id,
            'rule_id': self.rule_id,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'evidence': self.evidence,
            'cwe': self.cwe,
            'owasp': self.owasp,
            'cvss': self.cvss,
            'source': self.source,
            'status': self.status,
            'endpoint': self.endpoint,
            'parameter': self.parameter,
            'payload': self.payload,
            'confidence': self.confidence,
            'suppressed': self.suppressed,
            'suppression_reason': self.suppression_reason,
            'suppression_approver': self.suppression_approver,
            'suppression_expires': self.suppression_expires,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'status_history': self.status_history,
        }


class FindingManager:
    """Quản lý findings: tạo, lifecycle, duplicate correlation, delta."""

    def __init__(self):
        self.findings = {}
        self._next_id = 1
        self.scan_snapshots = []

    def create_finding(self, asset_id, rule_id, severity, title, **kwargs):
        """Tạo finding mới."""
        finding_id = f"FND-{self._next_id:06d}"
        self._next_id += 1
        finding = Finding(finding_id, asset_id, rule_id, severity, title, **kwargs)
        self.findings[finding_id] = finding
        return finding

    def get_finding(self, finding_id):
        return self.findings.get(finding_id)

    def create_finding_from_unified(self, unified_finding, asset_id=None):
        """Tạo Finding từ một UnifiedFinding (correlation_engine.py).

        Đây là cầu nối giữa Correlation & Deduplication Engine (chuẩn hoá +
        dedup đa nguồn theo đặc tả §25) và FindingManager (vòng đời
        Suspected→Verified→Confirmed→Resolved/Accepted Risk + suppression
        workflow theo đặc tả §11). Trước đây hai module này tồn tại song
        song, không kết nối — CorrelationEngine dedup xong không đi đâu cả,
        còn FindingManager tự dedup lại bằng key khác (correlate_duplicates).

        Confidence do CorrelationEngine tính (Suspected/Verified/Confirmed,
        tăng dần theo số detection source đồng thuận) được dùng làm status
        khởi tạo — một finding được ≥2 scanner xác nhận sẽ vào thẳng
        'confirmed' thay vì phải nâng cấp thủ công từng bước.
        """
        return self.create_finding(
            asset_id=asset_id or unified_finding.asset,
            rule_id=unified_finding.cwe or unified_finding.vulnerability,
            severity=unified_finding.severity,
            title=unified_finding.vulnerability,
            description=unified_finding.evidence,
            evidence={'detail': unified_finding.evidence,
                      'sources': sorted(unified_finding.detection_sources)},
            cwe=unified_finding.cwe,
            cvss=unified_finding.cvss,
            owasp=unified_finding.owasp_mapping,
            source=unified_finding.detection_source,
            detection_method=unified_finding.detection_source,
            status=unified_finding.confidence.lower(),
            endpoint=unified_finding.location,
            confidence=unified_finding.confidence,
        )

    def import_from_correlation_engine(self, unified_findings, asset_id=None):
        """Ingest toàn bộ output đã dedup của CorrelationEngine — mỗi
        UnifiedFinding trở thành 1 Finding có đầy đủ vòng đời/suppression."""
        return [self.create_finding_from_unified(uf, asset_id=asset_id) for uf in unified_findings]

    def list_findings(self, status=None, severity=None, asset_id=None):
        """Lọc danh sách findings."""
        result = []
        for f in self.findings.values():
            if status and f.status != status:
                continue
            if severity and f.severity != severity:
                continue
            if asset_id and f.asset_id != asset_id:
                continue
            result.append(f)
        return result

    def correlate_duplicates(self):
        """
        Duplicate Correlation — gom finding trùng theo đúng khoá đặc tả §25.1:
        Asset + Endpoint/URL + Vulnerability Class (CWE) + Parameter.

        LƯU Ý: trước đây key gồm cả `evidence_hash()` (băm SHA-256 của toàn bộ
        evidence dict) — nghĩa là 2 finding CÙNG lỗ hổng, CÙNG endpoint,
        CÙNG rule nhưng evidence hơi khác nhau (vd response body khác 1 ký
        tự do timestamp/token động) sẽ KHÔNG được coi là trùng, ngược lại
        chính xác điều mà Correlation Engine (đặc tả §25) tồn tại để giải
        quyết. Đã bỏ evidence_hash khỏi khoá, dùng đúng tổ hợp spec quy định.
        """
        groups = {}
        for f in self.findings.values():
            if f.suppressed:
                continue
            key = f"{f.asset_id}|{f.endpoint}|{f.cwe or f.rule_id}|{f.parameter or ''}"
            if key not in groups:
                groups[key] = []
            groups[key].append(f)

        duplicate_info = []
        for key, group in groups.items():
            if len(group) > 1:
                primary = group[0]
                for dup in group[1:]:
                    dup.duplicate_of = primary.finding_id
                duplicate_info.append({
                    'key': key,
                    'count': len(group),
                    'primary': primary.finding_id,
                    'duplicates': [d.finding_id for d in group[1:]],
                })
        return duplicate_info

    def take_snapshot(self, scan_id, target):
        """Lưu snapshot scan hiện tại để so sánh delta."""
        snapshot = {
            'scan_id': scan_id,
            'target': target,
            'taken_at': datetime.now().isoformat(),
            'findings': {fid: f.to_dict() for fid, f in self.findings.items()},
        }
        self.scan_snapshots.append(snapshot)
        return snapshot

    def compare_snapshots(self, previous_scan_id, current_scan_id):
        """So sánh delta: New / Fixed / Unchanged / Reopened."""
        prev = None
        curr = None
        for snap in self.scan_snapshots:
            if snap['scan_id'] == previous_scan_id:
                prev = snap
            if snap['scan_id'] == current_scan_id:
                curr = snap
        if not prev or not curr:
            return None

        prev_keys = set(prev['findings'].keys())
        curr_keys = set(curr['findings'].keys())

        new = set()
        fixed = set()
        unchanged = set()
        reopened = set()

        common = prev_keys & curr_keys
        for fid in common:
            prev_status = prev['findings'][fid]['status']
            curr_status = curr['findings'][fid]['status']
            if prev_status != 'resolved' and curr_status == 'resolved':
                fixed.add(fid)
            elif prev_status == 'resolved' and curr_status != 'resolved':
                reopened.add(fid)
                new.add(fid)
            else:
                unchanged.add(fid)

        new.update(curr_keys - prev_keys)
        fixed.update(prev_keys - curr_keys)

        return {
            'previous_scan': previous_scan_id,
            'current_scan': current_scan_id,
            'new': sorted(new),
            'fixed': sorted(fixed),
            'unchanged': sorted(unchanged),
            'reopened': sorted(reopened),
            'summary': {
                'new_count': len(new),
                'fixed_count': len(fixed),
                'unchanged_count': len(unchanged),
                'reopened_count': len(reopened),
            }
        }

    def get_stats(self):
        """Thống kê finding theo status và severity."""
        by_status = {}
        by_severity = {}
        suppressed = 0
        for f in self.findings.values():
            by_status[f.status] = by_status.get(f.status, 0) + 1
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            if f.suppressed:
                suppressed += 1

        return {
            'total': len(self.findings),
            'by_status': by_status,
            'by_severity': by_severity,
            'suppressed': suppressed,
        }