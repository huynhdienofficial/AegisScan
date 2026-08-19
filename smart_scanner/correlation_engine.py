"""
Correlation & Deduplication Engine — Unified Finding Data Model (đặc tả v3.3 §25).

Khi nhiều detection engine (Web DAST scanners, Infra scanners, Governance
checks...) cùng chạy trên một target, cùng một lỗ hổng có thể được nhiều
engine báo cáo với format khác nhau — nếu không chuẩn hoá, report sẽ hiện
trùng lặp (một lỗi SQLi xuất hiện 2-3 lần dưới các tên/format khác nhau),
không dùng được cho Risk Engine hay Dashboard.

Engine này:
1. `normalize()` — map output thô của bất kỳ scanner nào (dict với các key
   tuỳ biến như 'type'/'vulnerability', 'url'/'endpoint', 'detail'/'evidence'...)
   về đúng 15 trường bắt buộc của Unified Finding Data Model (§25.2).
2. `correlate()` — khớp trùng theo tổ hợp (Asset + Endpoint + CWE/Vulnerability
   class + Parameter) → sinh evidence hash; nếu ≥2 nguồn khác nhau cùng khớp
   key này thì gộp thành 1 finding và NÂNG Confidence (Suspected → Verified
   → Confirmed) thay vì hiển thị N bản ghi trùng.
"""
import hashlib
from datetime import datetime


# 15 trường bắt buộc theo đặc tả §25.2
UNIFIED_FINDING_FIELDS = (
    'asset', 'location', 'vulnerability', 'cwe', 'cve', 'cvss',
    'owasp_mapping', 'severity', 'evidence', 'detection_source',
    'confidence', 'remediation', 'false_positive_status',
    'first_detected', 'last_detected', 'risk_score',
)

# Suspected (1 nguồn) → Verified (xác minh non-destructive) → Confirmed (≥2 nguồn đồng thuận)
CONFIDENCE_ORDER = ('Suspected', 'Verified', 'Confirmed')

# Heuristic map free-text vulnerability name -> CWE, dùng khi scanner gốc
# không tự gắn CWE (đa số scanner trong repo hiện tại không gắn).
_VULN_TO_CWE = {
    'sql injection': 'CWE-89', 'sqli': 'CWE-89',
    'xss': 'CWE-79', 'cross-site scripting': 'CWE-79',
    'command injection': 'CWE-78', 'rce': 'CWE-78',
    'ssrf': 'CWE-918',
    'path traversal': 'CWE-22', 'lfi': 'CWE-98', 'rfi': 'CWE-98',
    'ssti': 'CWE-1336',
    'xxe': 'CWE-611',
    'csrf': 'CWE-352',
    'idor': 'CWE-639',
    'open redirect': 'CWE-601',
    'insecure cookie': 'CWE-614',
    'missing security header': 'CWE-693',
    'request smuggling': 'CWE-444',
    'jwt': 'CWE-347',
}


class UnifiedFinding:
    """Một finding đã chuẩn hoá theo schema §25.2 (15 trường)."""

    def __init__(self, asset='', location='', vulnerability='', cwe=None, cve=None,
                 cvss=None, owasp_mapping=None, severity='Info', evidence='',
                 detection_source='unknown', confidence='Suspected', remediation=None,
                 false_positive_status='open', first_detected=None, last_detected=None,
                 risk_score=None, raw=None):
        self.asset = asset
        self.location = location
        self.vulnerability = vulnerability
        self.cwe = cwe
        self.cve = cve
        self.cvss = cvss
        self.owasp_mapping = owasp_mapping
        self.severity = severity
        self.evidence = evidence
        self.detection_source = detection_source
        self.confidence = confidence if confidence in CONFIDENCE_ORDER else 'Suspected'
        self.remediation = remediation
        self.false_positive_status = false_positive_status
        now = datetime.now().isoformat()
        self.first_detected = first_detected or now
        self.last_detected = last_detected or now
        self.risk_score = risk_score
        # Nguồn gốc thô — không thuộc 15 trường bắt buộc nhưng hữu ích để
        # truy vết/debug, không dùng cho correlation hay report chuẩn.
        self.raw_sources = [raw] if raw is not None else []
        self.detection_sources = {detection_source}

    def dedup_key(self):
        """Khoá khớp trùng: Asset + Location + CWE (hoặc vulnerability nếu
        chưa map được CWE) + parameter (nếu location có query string)."""
        vuln_class = self.cwe or self.vulnerability.strip().lower()
        return hashlib.sha256(
            f"{self.asset}|{self.location}|{vuln_class}".encode()
        ).hexdigest()[:20]

    def merge(self, other):
        """Gộp một finding trùng khoá vào finding này — nâng confidence khi
        có thêm nguồn phát hiện độc lập."""
        if other.detection_source not in self.detection_sources:
            self.detection_sources.add(other.detection_source)
            self.detection_source = ', '.join(sorted(self.detection_sources))
            current_idx = CONFIDENCE_ORDER.index(self.confidence)
            self.confidence = CONFIDENCE_ORDER[min(current_idx + 1, len(CONFIDENCE_ORDER) - 1)]
        self.raw_sources.extend(other.raw_sources)
        if other.last_detected > self.last_detected:
            self.last_detected = other.last_detected
        if other.first_detected < self.first_detected:
            self.first_detected = other.first_detected
        if not self.cwe and other.cwe:
            self.cwe = other.cwe
        if not self.cve and other.cve:
            self.cve = other.cve
        if (self.cvss or 0) < (other.cvss or 0):
            self.cvss = other.cvss
        if (self.risk_score or 0) < (other.risk_score or 0):
            self.risk_score = other.risk_score
        return self

    def to_dict(self):
        d = {field: getattr(self, field) for field in UNIFIED_FINDING_FIELDS}
        d['dedup_key'] = self.dedup_key()
        d['sources_agreeing'] = len(self.detection_sources)
        return d


class CorrelationEngine:
    """Chuẩn hoá + khớp trùng finding từ nhiều detection engine."""

    def __init__(self, asset=''):
        self.asset = asset

    def normalize(self, raw_finding, detection_source, asset=None):
        """Map một finding thô (dict tuỳ format) sang UnifiedFinding."""
        f = raw_finding
        vulnerability = str(f.get('type') or f.get('vulnerability') or f.get('title') or 'Unknown')
        location = str(f.get('url') or f.get('endpoint') or f.get('location') or f.get('target') or '')
        severity = str(f.get('severity') or 'Info').title()
        evidence = str(f.get('evidence') or f.get('detail') or f.get('payload') or '')
        confidence_raw = str(f.get('confidence') or 'Suspected').title()
        confidence = confidence_raw if confidence_raw in CONFIDENCE_ORDER else 'Suspected'

        cwe = f.get('cwe')
        if not cwe:
            vuln_lower = vulnerability.lower()
            for key, mapped in _VULN_TO_CWE.items():
                if key in vuln_lower:
                    cwe = mapped
                    break

        return UnifiedFinding(
            asset=asset if asset is not None else self.asset,
            location=location,
            vulnerability=vulnerability,
            cwe=cwe,
            cve=f.get('cve'),
            cvss=f.get('cvss'),
            owasp_mapping=f.get('owasp_mapping'),
            severity=severity,
            evidence=evidence,
            detection_source=detection_source,
            confidence=confidence,
            remediation=f.get('remediation'),
            false_positive_status=f.get('false_positive_status', 'open'),
            risk_score=f.get('risk_score'),
            raw=f,
        )

    def correlate(self, unified_findings):
        """Khớp trùng danh sách UnifiedFinding — trả về danh sách đã gộp,
        không còn 2 bản ghi trùng key hiển thị riêng lẻ."""
        merged = {}
        order = []
        for finding in unified_findings:
            key = finding.dedup_key()
            if key in merged:
                merged[key].merge(finding)
            else:
                merged[key] = finding
                order.append(key)
        return [merged[k] for k in order]

    def normalize_and_correlate(self, findings_by_source):
        """Tiện ích: nhận dict {detection_source: [raw_finding, ...]} → trả
        về list UnifiedFinding đã dedup, sẵn sàng cho report/risk engine."""
        unified = []
        for source, findings in findings_by_source.items():
            for raw in findings:
                unified.append(self.normalize(raw, source))
        return self.correlate(unified)
