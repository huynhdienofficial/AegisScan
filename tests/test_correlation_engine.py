import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMART = ROOT / 'smart_scanner'
sys.path.insert(0, str(SMART))

from correlation_engine import CorrelationEngine, UnifiedFinding, UNIFIED_FINDING_FIELDS
from finding_management import FindingManager


def test_normalize_maps_arbitrary_scanner_dict_to_unified_schema():
    engine = CorrelationEngine(asset='asset-1')
    raw = {
        'type': 'SQL Injection', 'url': 'https://app.example.com/login?id=1',
        'severity': 'high', 'confidence': 'medium', 'detail': "' OR 1=1--",
    }
    unified = engine.normalize(raw, detection_source='zap')
    d = unified.to_dict()

    for field in UNIFIED_FINDING_FIELDS:
        assert field in d
    assert d['vulnerability'] == 'SQL Injection'
    assert d['cwe'] == 'CWE-89'  # heuristic map hoạt động
    assert d['severity'] == 'High'
    assert d['detection_source'] == 'zap'
    assert d['confidence'] == 'Suspected'  # 1 nguồn duy nhất


def test_correlate_merges_same_vuln_from_two_sources_and_raises_confidence():
    engine = CorrelationEngine(asset='asset-1')
    finding_zap = engine.normalize(
        {'type': 'SQL Injection', 'url': 'https://app.example.com/login?id=1', 'severity': 'High'},
        detection_source='zap',
    )
    finding_nuclei = engine.normalize(
        {'type': 'SQL Injection', 'url': 'https://app.example.com/login?id=1', 'severity': 'High', 'cve': 'CVE-2021-9999'},
        detection_source='nuclei',
    )

    merged = engine.correlate([finding_zap, finding_nuclei])

    # Cùng asset+endpoint+CWE → gộp thành 1 finding duy nhất, không hiện 2 lần
    assert len(merged) == 1
    result = merged[0].to_dict()
    assert result['sources_agreeing'] == 2
    assert 'zap' in result['detection_source'] and 'nuclei' in result['detection_source']
    # 2 nguồn đồng thuận → Confidence nâng từ Suspected lên Verified
    assert result['confidence'] == 'Verified'
    # Field còn thiếu ở finding đầu được bổ sung từ finding thứ hai khi merge
    assert result['cve'] == 'CVE-2021-9999'


def test_correlate_keeps_different_vulns_separate():
    engine = CorrelationEngine(asset='asset-1')
    xss = engine.normalize({'type': 'XSS', 'url': 'https://app.example.com/search?q=x'}, detection_source='zap')
    sqli = engine.normalize({'type': 'SQL Injection', 'url': 'https://app.example.com/search?q=x'}, detection_source='zap')

    merged = engine.correlate([xss, sqli])
    assert len(merged) == 2


def test_normalize_and_correlate_convenience_helper():
    engine = CorrelationEngine(asset='asset-1')
    findings_by_source = {
        'zap': [{'type': 'XSS', 'url': 'https://a.com/x', 'severity': 'Medium'}],
        'nuclei': [{'type': 'XSS', 'url': 'https://a.com/x', 'severity': 'Medium'}],
        'wapiti': [{'type': 'CSRF', 'url': 'https://a.com/form', 'severity': 'Low'}],
    }
    merged = engine.normalize_and_correlate(findings_by_source)
    # 2 XSS trùng gộp thành 1, CSRF riêng biệt → tổng 2 finding
    assert len(merged) == 2
    xss_result = next(f for f in merged if f.vulnerability == 'XSS')
    assert xss_result.dedup_key() is not None
    assert len(xss_result.detection_sources) == 2


# ─── Cầu nối CorrelationEngine → FindingManager ────────────────────

def test_import_from_correlation_engine_creates_findings_with_lifecycle():
    """create_finding_from_unified/import_from_correlation_engine phải tạo
    Finding thật (có suppress/update_status) từ UnifiedFinding đã dedup —
    trước đây 2 module này không kết nối với nhau."""
    engine = CorrelationEngine(asset='asset-1')
    findings_by_source = {
        'zap': [{'type': 'SQL Injection', 'url': 'https://a.com/login?id=1', 'severity': 'Critical'}],
        'nuclei': [{'type': 'SQL Injection', 'url': 'https://a.com/login?id=1', 'severity': 'Critical'}],
    }
    unified = engine.normalize_and_correlate(findings_by_source)
    assert len(unified) == 1  # 2 nguồn trùng → dedup thành 1

    mgr = FindingManager()
    findings = mgr.import_from_correlation_engine(unified, asset_id='AST-0001')

    assert len(findings) == 1
    f = findings[0]
    assert f.asset_id == 'AST-0001'
    assert f.title == 'SQL Injection'
    assert f.cwe == 'CWE-89'
    # 2 nguồn đồng thuận → CorrelationEngine đã nâng confidence lên Verified,
    # FindingManager dùng ngay làm status khởi tạo thay vì luôn bắt đầu ở suspected
    assert f.status == 'verified'
    assert 'zap' in f.evidence['sources'] and 'nuclei' in f.evidence['sources']

    # Finding tạo ra vẫn có đầy đủ vòng đời/suppression như finding tạo trực tiếp
    f.suppress(reason='Accepted risk', approver='admin', expires_in_days=10)
    assert f.suppressed is True
    f.update_status('confirmed')
    assert f.status == 'confirmed'


def test_correlate_duplicates_uses_asset_endpoint_cwe_parameter_key():
    """Regression: trước đây correlate_duplicates() yêu cầu evidence_hash
    KHỚP CHÍNH XÁC mới coi là trùng — 2 finding cùng lỗ hổng/endpoint nhưng
    evidence khác 1 chi tiết động (vd timestamp) sẽ KHÔNG được gộp, sai với
    khoá spec §25.1 (Asset+Endpoint+CWE+Parameter, không gồm evidence)."""
    mgr = FindingManager()
    f1 = mgr.create_finding(
        asset_id='AST-0001', rule_id='SQLI-001', severity='Critical', title='SQLi',
        endpoint='https://a.com/login', parameter='user', cwe='CWE-89',
        evidence={'response_snapshot_at': '2026-01-01T00:00:00'},
    )
    f2 = mgr.create_finding(
        asset_id='AST-0001', rule_id='SQLI-001', severity='Critical', title='SQLi',
        endpoint='https://a.com/login', parameter='user', cwe='CWE-89',
        evidence={'response_snapshot_at': '2026-01-01T00:05:00'},  # evidence khác — vẫn phải coi là trùng
    )

    dups = mgr.correlate_duplicates()
    assert len(dups) == 1
    assert dups[0]['count'] == 2
    assert f2.duplicate_of == f1.finding_id
